package plc

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/atscan/atscanner/internal/log"
	"github.com/atscan/atscanner/internal/storage"
	"github.com/klauspost/compress/zstd"
)

type BundleManager struct {
	dir     string
	enabled bool
	encoder *zstd.Encoder
	decoder *zstd.Decoder
	db      storage.Database
}

func NewBundleManager(dir string, enabled bool, db storage.Database) (*BundleManager, error) {
	if !enabled {
		return &BundleManager{enabled: false}, nil
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create bundle dir: %w", err)
	}

	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBetterCompression))
	if err != nil {
		return nil, err
	}

	decoder, err := zstd.NewReader(nil)
	if err != nil {
		return nil, err
	}

	return &BundleManager{
		dir:     dir,
		enabled: true,
		encoder: encoder,
		decoder: decoder,
		db:      db,
	}, nil
}

func (bm *BundleManager) Close() {
	if bm.encoder != nil {
		bm.encoder.Close()
	}
	if bm.decoder != nil {
		bm.decoder.Close()
	}
}

// GetBundleFilename returns filename for bundle number (6-digit decimal, JSONL format)
func (bm *BundleManager) GetBundleFilename(bundleNumber int) string {
	return fmt.Sprintf("%06d.jsonl.zst", bundleNumber)
}

// GetBundlePath returns full path for bundle number
func (bm *BundleManager) GetBundlePath(bundleNumber int) string {
	return filepath.Join(bm.dir, bm.GetBundleFilename(bundleNumber))
}

// BundleExists checks if bundle file exists locally
func (bm *BundleManager) BundleExists(bundleNumber int) bool {
	_, err := os.Stat(bm.GetBundlePath(bundleNumber))
	return err == nil
}

// LoadBundle returns exactly 1000 unique operations by fetching additional batches if needed
func (bm *BundleManager) LoadBundle(ctx context.Context, bundleNumber int, plcClient *Client) ([]PLCOperation, bool, error) {
	if !bm.enabled {
		return nil, false, fmt.Errorf("bundle manager disabled")
	}

	path := bm.GetBundlePath(bundleNumber)

	// Try to load from local file first
	if bm.BundleExists(bundleNumber) {
		log.Verbose("→ Loading bundle %06d from local file", bundleNumber)

		// Check if bundle exists in database
		dbBundle, dbErr := bm.db.GetBundleByNumber(ctx, bundleNumber)
		bundleInDB := dbErr == nil && dbBundle != nil

		if bundleInDB {
			// Verify compressed file hash
			if dbBundle.CompressedHash != "" {
				valid, err := bm.verifyBundleHash(path, dbBundle.CompressedHash)
				if err != nil {
					log.Error("Warning: failed to verify compressed hash for bundle %06d: %v", bundleNumber, err)
				} else if !valid {
					log.Error("⚠ Compressed hash mismatch for bundle %06d! Re-fetching...", bundleNumber)
					os.Remove(path)
					return bm.LoadBundle(ctx, bundleNumber, plcClient)
				} else {
					log.Verbose("✓ Hash verified for bundle %06d", bundleNumber)
				}
			}
		}

		// Load operations from file
		operations, err := bm.loadBundleFromFile(path)
		if err != nil {
			return nil, false, fmt.Errorf("failed to load bundle from file: %w", err)
		}

		// If not in database, index it now
		if !bundleInDB {
			// Calculate both hashes
			fileData, err := os.ReadFile(path)
			if err != nil {
				log.Error("Warning: failed to read file: %v", err)
			} else {
				compressedHash := bm.calculateHash(fileData)

				// Calculate uncompressed hash
				var jsonlData []byte
				for i, op := range operations {
					jsonlData = append(jsonlData, op.RawJSON...)
					if i < len(operations)-1 {
						jsonlData = append(jsonlData, '\n')
					}
				}
				uncompressedHash := bm.calculateHash(jsonlData)

				if err := bm.indexBundleWithHash(ctx, bundleNumber, operations, path, uncompressedHash, compressedHash); err != nil {
					log.Error("Warning: failed to index bundle: %v", err)
				} else {
					log.Info("✓ Indexed bundle %06d", bundleNumber)
				}
			}
		}

		// If loaded from disk, it's always complete
		return operations, true, nil
	}

	// Bundle doesn't exist locally - fetch from PLC directory
	log.Info("→ Bundle %06d not found locally, fetching from PLC directory...", bundleNumber)

	var afterTimestamp string
	var prevBoundaryCIDs map[string]bool

	if bundleNumber > 1 {
		prevBundle, err := bm.db.GetBundleByNumber(ctx, bundleNumber-1)
		if err == nil && prevBundle != nil {
			afterTimestamp = prevBundle.EndTime.Format(time.RFC3339Nano)

			// Get boundary CIDs from previous bundle
			if len(prevBundle.BoundaryCIDs) > 0 {
				prevBoundaryCIDs = make(map[string]bool)
				for _, cid := range prevBundle.BoundaryCIDs {
					prevBoundaryCIDs[cid] = true
				}
				log.Verbose("  Using %d boundary CIDs from previous bundle", len(prevBoundaryCIDs))
			} else {
				// Fallback: load previous bundle's operations
				prevPath := bm.GetBundlePath(bundleNumber - 1)
				if bm.BundleExists(bundleNumber - 1) {
					prevOps, err := bm.loadBundleFromFile(prevPath)
					if err == nil {
						_, prevBoundaryCIDs = GetBoundaryCIDs(prevOps)
						log.Verbose("  Computed %d boundary CIDs from previous bundle file", len(prevBoundaryCIDs))
					}
				}
			}
		}
	}

	// Collect operations until we have exactly 1000 unique ones
	var allOperations []PLCOperation
	seenCIDs := make(map[string]bool)

	// Track what we've already seen from previous bundle
	for cid := range prevBoundaryCIDs {
		seenCIDs[cid] = true
	}

	currentAfter := afterTimestamp
	maxFetches := 10 // Safety limit
	fetchCount := 0

	for len(allOperations) < 1000 && fetchCount < maxFetches {
		fetchCount++

		// Calculate how many more operations we need
		remaining := 1000 - len(allOperations)

		// Determine fetch size based on remaining operations
		var fetchSize int
		if fetchCount == 1 {
			// First fetch: always get 1000
			fetchSize = 1000
		} else if remaining < 100 {
			// Need less than 100: fetch 50-100 (small buffer for duplicates)
			fetchSize = 50
		} else if remaining < 500 {
			// Need 100-500: fetch 200 (some buffer for duplicates)
			fetchSize = 200
		} else {
			// Need 500+: fetch 1000
			fetchSize = 1000
		}

		// Fetch next batch
		rawOperations, err := bm.fetchBundleFromPLCWithCount(ctx, plcClient, currentAfter, fetchSize)
		if err != nil {
			return nil, false, fmt.Errorf("failed to fetch bundle from PLC: %w", err)
		}

		if len(rawOperations) == 0 {
			// No more data available
			log.Info("  No more operations available after %d fetches", fetchCount)
			break
		}

		log.Verbose("  Fetch #%d: requested %d, got %d raw operations (need %d more)",
			fetchCount, fetchSize, len(rawOperations), remaining)

		// Filter out duplicates and add unique operations
		newOpsAdded := 0
		for _, op := range rawOperations {
			if !seenCIDs[op.CID] {
				seenCIDs[op.CID] = true
				allOperations = append(allOperations, op)
				newOpsAdded++

				if len(allOperations) >= 1000 {
					break
				}
			}
		}

		log.Verbose("  Added %d unique operations (total: %d/1000)", newOpsAdded, len(allOperations))

		// If we added no new operations, we're stuck in a loop
		if newOpsAdded == 0 {
			log.Error("  No new unique operations found, stopping")
			break
		}

		// Update cursor for next fetch
		if len(rawOperations) > 0 {
			lastOp := rawOperations[len(rawOperations)-1]
			currentAfter = lastOp.CreatedAt.Format(time.RFC3339Nano)
		}

		// If PLC returned less than requested, we've reached the end
		if len(rawOperations) < fetchSize {
			log.Info("  Reached end of PLC data (got %d < %d requested)", len(rawOperations), fetchSize)
			break
		}
	}

	// Check if we got exactly 1000 operations
	isComplete := len(allOperations) >= 1000

	if len(allOperations) > 1000 {
		// Trim to exactly 1000
		allOperations = allOperations[:1000]
	}

	log.Info("  Collected %d unique operations after %d fetches (complete=%v)",
		len(allOperations), fetchCount, isComplete)

	// Only save as bundle if complete
	if isComplete {
		// Save bundle with both hashes
		uncompressedHash, compressedHash, err := bm.saveBundleFileWithHash(path, allOperations)
		if err != nil {
			log.Error("Warning: failed to save bundle file: %v", err)
		} else {
			// Index with both hashes
			if err := bm.indexBundleWithHash(ctx, bundleNumber, allOperations, path, uncompressedHash, compressedHash); err != nil {
				log.Error("Warning: failed to index bundle: %v", err)
			} else {
				log.Info("✓ Bundle %06d saved [1000 ops, hash: %s, compressed: %s]",
					bundleNumber, uncompressedHash[:16]+"...", compressedHash[:16]+"...")
			}
		}
	}

	return allOperations, isComplete, nil
}

// fetchBundleFromPLCWithCount fetches operations with a specific count
func (bm *BundleManager) fetchBundleFromPLCWithCount(ctx context.Context, client *Client, afterTimestamp string, count int) ([]PLCOperation, error) {
	return client.Export(ctx, ExportOptions{
		Count: count,
		After: afterTimestamp,
	})
}

// saveBundleFileWithHash - NO trailing newline
func (bm *BundleManager) saveBundleFileWithHash(path string, operations []PLCOperation) (string, string, error) {
	var jsonlData []byte
	for i, op := range operations {
		jsonlData = append(jsonlData, op.RawJSON...)

		// Add newline ONLY between operations (not after last)
		if i < len(operations)-1 {
			jsonlData = append(jsonlData, '\n')
		}
	}

	uncompressedHash := bm.calculateHash(jsonlData)
	compressed := bm.encoder.EncodeAll(jsonlData, nil)
	compressedHash := bm.calculateHash(compressed)

	if err := os.WriteFile(path, compressed, 0644); err != nil {
		return "", "", err
	}

	return uncompressedHash, compressedHash, nil
}

// fetchBundleFromPLC fetches operations from PLC directory (returns RAW operations)
func (bm *BundleManager) fetchBundleFromPLC(ctx context.Context, client *Client, afterTimestamp string) ([]PLCOperation, error) {
	// Just fetch - no deduplication here
	return client.Export(ctx, ExportOptions{
		Count: 1000,
		After: afterTimestamp,
	})
}

// StripBoundaryDuplicates removes operations that were already seen on the previous page
// This is exported so it can be used in verification
func StripBoundaryDuplicates(operations []PLCOperation, boundaryTimestamp string, prevBoundaryCIDs map[string]bool) []PLCOperation {
	if len(operations) == 0 {
		return operations
	}

	boundaryTime, err := time.Parse(time.RFC3339Nano, boundaryTimestamp)
	if err != nil {
		return operations
	}

	// Skip operations at the start that match the boundary
	startIdx := 0
	for startIdx < len(operations) {
		op := operations[startIdx]

		// If timestamp is AFTER boundary, we're past duplicates
		if op.CreatedAt.After(boundaryTime) {
			break
		}

		// Same timestamp - check if we've seen this CID before
		if op.CreatedAt.Equal(boundaryTime) {
			if prevBoundaryCIDs[op.CID] {
				// This is a duplicate, skip it
				startIdx++
				continue
			}
			// Same timestamp but new CID - keep it
			break
		}

		// Earlier timestamp (shouldn't happen)
		break
	}

	return operations[startIdx:]
}

// Keep the private version for internal use
func stripBoundaryDuplicates(operations []PLCOperation, boundaryTimestamp string, prevBoundaryCIDs map[string]bool) []PLCOperation {
	return StripBoundaryDuplicates(operations, boundaryTimestamp, prevBoundaryCIDs)
}

// GetBoundaryCIDs returns all CIDs that share the same timestamp as the last operation
func GetBoundaryCIDs(operations []PLCOperation) (time.Time, map[string]bool) {
	if len(operations) == 0 {
		return time.Time{}, nil
	}

	lastOp := operations[len(operations)-1]
	boundaryTime := lastOp.CreatedAt
	cidSet := make(map[string]bool)

	// Walk backwards from the end, collecting all CIDs with the same timestamp
	for i := len(operations) - 1; i >= 0; i-- {
		op := operations[i]
		if op.CreatedAt.Equal(boundaryTime) {
			cidSet[op.CID] = true
		} else {
			// Different timestamp, we're done
			break
		}
	}

	return boundaryTime, cidSet
}

// saveBundleFile (keep for compatibility, calls saveBundleFileWithHash)
func (bm *BundleManager) saveBundleFile(path string, operations []PLCOperation) error {
	_, _, err := bm.saveBundleFileWithHash(path, operations) // ✅ All 3 values
	return err
}

// loadBundleFromFile loads operations from bundle file (JSONL format)
func (bm *BundleManager) loadBundleFromFile(path string) ([]PLCOperation, error) {
	// Read compressed file
	compressedData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read bundle file: %w", err)
	}

	// Decompress
	decompressed, err := bm.decoder.DecodeAll(compressedData, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress bundle: %w", err)
	}

	// Parse JSONL (newline-delimited JSON)
	var operations []PLCOperation
	scanner := bufio.NewScanner(bytes.NewReader(decompressed))

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()

		// Skip empty lines
		if len(line) == 0 {
			continue
		}

		var op PLCOperation
		if err := json.Unmarshal(line, &op); err != nil {
			return nil, fmt.Errorf("failed to parse operation on line %d: %w", lineNum, err)
		}

		// CRITICAL: Store the original raw JSON bytes
		op.RawJSON = make([]byte, len(line))
		copy(op.RawJSON, line)

		operations = append(operations, op)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading JSONL: %w", err)
	}

	return operations, nil
}

// indexBundleWithHash stores bundle with both hashes
func (bm *BundleManager) indexBundleWithHash(ctx context.Context, bundleNumber int, operations []PLCOperation, path string, uncompressedHash, compressedHash string) error {
	// Get previous bundle's hash (uncompressed)
	var prevBundleHash string
	if bundleNumber > 1 {
		prevBundle, err := bm.db.GetBundleByNumber(ctx, bundleNumber-1)
		if err == nil && prevBundle != nil {
			prevBundleHash = prevBundle.Hash // Use uncompressed hash for chain
			log.Verbose("  Linking to previous bundle %06d (hash: %s)", bundleNumber-1, prevBundleHash[:16]+"...")
		}
	}

	// Extract unique DIDs
	didSet := make(map[string]bool)
	for _, op := range operations {
		didSet[op.DID] = true
	}

	dids := make([]string, 0, len(didSet))
	for did := range didSet {
		dids = append(dids, did)
	}

	// Get compressed file size
	fileInfo, _ := os.Stat(path)
	compressedSize := int64(0)
	if fileInfo != nil {
		compressedSize = fileInfo.Size()
	}

	bundle := &storage.PLCBundle{
		BundleNumber:   bundleNumber,
		StartTime:      operations[0].CreatedAt,
		EndTime:        operations[len(operations)-1].CreatedAt,
		DIDs:           dids,
		Hash:           uncompressedHash, // Primary hash (JSONL)
		CompressedHash: compressedHash,   // File integrity hash
		CompressedSize: compressedSize,   // Compressed size
		PrevBundleHash: prevBundleHash,   // Chain link
		Compressed:     true,
		CreatedAt:      time.Now(),
	}

	return bm.db.CreateBundle(ctx, bundle)
}

// indexBundle (keep for compatibility) - FIX: Calculate both hashes
func (bm *BundleManager) indexBundle(ctx context.Context, bundleNumber int, operations []PLCOperation, path string) error {
	// Calculate compressed hash from file
	fileData, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	compressedHash := bm.calculateHash(fileData)

	// Calculate uncompressed hash from operations
	var jsonlData []byte
	for i, op := range operations {
		lineJSON, _ := json.Marshal(op)
		jsonlData = append(jsonlData, lineJSON...)

		// Add newline ONLY if not the last operation
		if i < len(operations)-1 {
			jsonlData = append(jsonlData, '\n')
		}
	}
	uncompressedHash := bm.calculateHash(jsonlData)

	return bm.indexBundleWithHash(ctx, bundleNumber, operations, path, uncompressedHash, compressedHash)
}

// Update CreateBundleFromMempool
func (bm *BundleManager) CreateBundleFromMempool(ctx context.Context, operations []PLCOperation) (int, error) {
	if !bm.enabled {
		return 0, fmt.Errorf("bundle manager disabled")
	}

	if len(operations) != 1000 {
		return 0, fmt.Errorf("bundle must have exactly 1000 operations, got %d", len(operations))
	}

	lastBundle, err := bm.db.GetLastBundleNumber(ctx)
	if err != nil {
		return 0, err
	}
	bundleNumber := lastBundle + 1

	path := bm.GetBundlePath(bundleNumber)

	// Save bundle with both hashes
	uncompressedHash, compressedHash, err := bm.saveBundleFileWithHash(path, operations)
	if err != nil {
		return 0, err
	}

	// Index bundle
	if err := bm.indexBundleWithHash(ctx, bundleNumber, operations, path, uncompressedHash, compressedHash); err != nil {
		return 0, err
	}

	log.Info("✓ Created bundle %06d from mempool (hash: %s)",
		bundleNumber, uncompressedHash[:16]+"...")

	return bundleNumber, nil
}

// EnsureBundleContinuity checks that all bundles from 1 to N exist
func (bm *BundleManager) EnsureBundleContinuity(ctx context.Context, targetBundle int) error {
	if !bm.enabled {
		return nil
	}

	for i := 1; i < targetBundle; i++ {
		if !bm.BundleExists(i) {
			// Check if in database
			_, err := bm.db.GetBundleByNumber(ctx, i)
			if err != nil {
				return fmt.Errorf("bundle %06d is missing (required for continuity)", i)
			}
		}
	}

	return nil
}

// GetStats returns bundle statistics
func (bm *BundleManager) GetStats(ctx context.Context) (int64, int64, error) {
	if !bm.enabled {
		return 0, 0, nil
	}
	return bm.db.GetBundleStats(ctx)
}

// calculateHash computes SHA256 hash of data
func (bm *BundleManager) calculateHash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// verifyBundleHash checks if file hash matches expected hash
func (bm *BundleManager) verifyBundleHash(path string, expectedHash string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}

	actualHash := bm.calculateHash(data)
	return actualHash == expectedHash, nil
}

// VerifyChain - FIX
func (bm *BundleManager) VerifyChain(ctx context.Context, endBundle int) error {
	if !bm.enabled {
		return fmt.Errorf("bundle manager disabled")
	}

	log.Info("Verifying bundle chain from 1 to %06d...", endBundle)

	for i := 1; i <= endBundle; i++ {
		bundle, err := bm.db.GetBundleByNumber(ctx, i)
		if err != nil {
			return fmt.Errorf("bundle %06d not found: %w", i, err)
		}

		// Compute file path
		filePath := bm.GetBundlePath(i)

		// Verify file hash
		valid, err := bm.verifyBundleHash(filePath, bundle.CompressedHash)
		if err != nil {
			return fmt.Errorf("bundle %06d hash verification failed: %w", i, err)
		}
		if !valid {
			return fmt.Errorf("bundle %06d compressed hash mismatch!", i)
		}

		// Verify chain link
		if i > 1 {
			prevBundle, err := bm.db.GetBundleByNumber(ctx, i-1)
			if err != nil {
				return fmt.Errorf("bundle %06d missing (required by %06d)", i-1, i)
			}

			if bundle.PrevBundleHash != prevBundle.Hash {
				return fmt.Errorf("bundle %06d chain broken! Expected prev_hash=%s, got=%s",
					i, prevBundle.Hash[:16], bundle.PrevBundleHash[:16])
			}
		}

		if i%100 == 0 {
			log.Verbose("  ✓ Verified bundles 1-%06d", i)
		}
	}

	log.Info("✓ Chain verification complete: bundles 1-%06d are valid and continuous", endBundle)
	return nil
}

// GetChainInfo returns information about the bundle chain
func (bm *BundleManager) GetChainInfo(ctx context.Context) (map[string]interface{}, error) {
	lastBundle, err := bm.db.GetLastBundleNumber(ctx)
	if err != nil {
		return nil, err
	}

	if lastBundle == 0 {
		return map[string]interface{}{
			"chain_length": 0,
			"status":       "empty",
		}, nil
	}

	// Quick check first and last
	firstBundle, err := bm.db.GetBundleByNumber(ctx, 1)
	if err != nil {
		return nil, err
	}

	lastBundleData, err := bm.db.GetBundleByNumber(ctx, lastBundle)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"chain_length":     lastBundle,
		"first_bundle":     1,
		"last_bundle":      lastBundle,
		"chain_start_time": firstBundle.StartTime,
		"chain_end_time":   lastBundleData.EndTime,
		"chain_head_hash":  lastBundleData.Hash,
	}, nil
}
