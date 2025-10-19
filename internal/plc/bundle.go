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

// LoadBundle - update to use computed path
func (bm *BundleManager) LoadBundle(ctx context.Context, bundleNumber int, plcClient *Client) ([]PLCOperation, error) {
	if !bm.enabled {
		return nil, fmt.Errorf("bundle manager disabled")
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

		// Load operations
		operations, err := bm.loadBundleFromFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to load bundle from file: %w", err)
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

					// Add newline ONLY if not the last operation
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

		return operations, nil
	}

	// Bundle doesn't exist locally - fetch from PLC directory
	log.Info("→ Bundle %06d not found locally, fetching from PLC directory...", bundleNumber)

	// ... rest of fetching logic stays the same ...
	var afterTimestamp string
	if bundleNumber > 1 {
		prevBundle, err := bm.db.GetBundleByNumber(ctx, bundleNumber-1)
		if err == nil && prevBundle != nil {
			afterTimestamp = prevBundle.EndTime.Format(time.RFC3339Nano)
		}
	}

	operations, err := bm.fetchBundleFromPLC(ctx, plcClient, afterTimestamp)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch bundle from PLC: %w", err)
	}

	// Save bundle with both hashes
	uncompressedHash, compressedHash, err := bm.saveBundleFileWithHash(path, operations)
	if err != nil {
		log.Error("Warning: failed to save bundle file: %v", err)
	}

	// Index with both hashes
	if err := bm.indexBundleWithHash(ctx, bundleNumber, operations, path, uncompressedHash, compressedHash); err != nil {
		log.Error("Warning: failed to index bundle: %v", err)
	}

	log.Info("✓ Bundle %06d saved [hash: %s, compressed: %s]",
		bundleNumber, uncompressedHash[:16]+"...", compressedHash[:16]+"...")

	return operations, nil
}

// saveBundleFileWithHash - NO trailing newline
func (bm *BundleManager) saveBundleFileWithHash(path string, operations []PLCOperation) (string, string, error) {
	var jsonlData []byte
	for i, op := range operations {
		if len(op.RawJSON) > 0 {
			jsonlData = append(jsonlData, op.RawJSON...)
		} else {
			lineJSON, err := json.Marshal(op)
			if err != nil {
				return "", "", fmt.Errorf("failed to marshal operation: %w", err)
			}
			jsonlData = append(jsonlData, lineJSON...)
		}

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

// fetchBundleFromPLC fetches operations from PLC directory using datetime cursor
func (bm *BundleManager) fetchBundleFromPLC(ctx context.Context, client *Client, afterTimestamp string) ([]PLCOperation, error) {
	// Fetch next batch of 1000 operations after the given timestamp
	return client.Export(ctx, ExportOptions{
		Count: 1000,
		After: afterTimestamp,
	})
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
	if len(operations) != 1000 {
		return fmt.Errorf("invalid number of operations: %d", len(operations))
	}

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
