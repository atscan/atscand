package plc

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

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

// LoadBundle loads a bundle by number (from file or fetches from PLC)
// LoadBundle loads a bundle by number with hash verification and auto-indexing
func (bm *BundleManager) LoadBundle(ctx context.Context, bundleNumber int, plcClient *Client) ([]PLCOperation, error) {
	if !bm.enabled {
		return nil, fmt.Errorf("bundle manager disabled")
	}

	path := bm.GetBundlePath(bundleNumber)

	// Try to load from local file first
	if bm.BundleExists(bundleNumber) {
		log.Printf("→ Loading bundle %06d from local file", bundleNumber)

		// Check if bundle exists in database
		dbBundle, dbErr := bm.db.GetBundleByNumber(ctx, bundleNumber)
		bundleInDB := dbErr == nil && dbBundle != nil

		if bundleInDB {
			// Verify hash if we have it
			if dbBundle.Hash != "" {
				valid, err := bm.verifyBundleHash(path, dbBundle.Hash)
				if err != nil {
					log.Printf("Warning: failed to verify hash for bundle %06d: %v", bundleNumber, err)
				} else if !valid {
					log.Printf("⚠ Hash mismatch for bundle %06d! File may be corrupted, re-fetching...", bundleNumber)
					os.Remove(path)
					return bm.LoadBundle(ctx, bundleNumber, plcClient)
				} else {
					log.Printf("✓ Hash verified for bundle %06d", bundleNumber)
				}
			}
		} else {
			// Bundle file exists but not in database - need to index it
			log.Printf("→ Bundle %06d exists on disk but not in database, indexing...", bundleNumber)
		}

		// Load operations from file
		operations, err := bm.loadBundleFromFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to load bundle from file: %w", err)
		}

		// If not in database, index it now
		if !bundleInDB {
			// Calculate hash from existing file
			fileData, err := os.ReadFile(path)
			if err != nil {
				log.Printf("Warning: failed to read file for hash calculation: %v", err)
			} else {
				hash := bm.calculateHash(fileData)

				if err := bm.indexBundleWithHash(ctx, bundleNumber, operations, path, hash); err != nil {
					log.Printf("Warning: failed to index bundle: %v", err)
				} else {
					log.Printf("✓ Indexed bundle %06d (hash: %s)", bundleNumber, hash[:16]+"...")
				}
			}
		}

		return operations, nil
	}

	// Bundle doesn't exist locally - fetch from PLC directory
	log.Printf("→ Bundle %06d not found locally, fetching from PLC directory...", bundleNumber)

	// Get the cursor timestamp from previous bundle
	var afterTimestamp string

	if bundleNumber > 1 {
		prevBundle, err := bm.db.GetBundleByNumber(ctx, bundleNumber-1)
		if err == nil && prevBundle != nil {
			afterTimestamp = prevBundle.EndTime.Format(time.RFC3339Nano)
			log.Printf("  Using cursor from bundle %06d: %s", bundleNumber-1, afterTimestamp)
		} else {
			// Try loading previous bundle from file
			if bm.BundleExists(bundleNumber - 1) {
				prevOps, err := bm.loadBundleFromFile(bm.GetBundlePath(bundleNumber - 1))
				if err == nil && len(prevOps) > 0 {
					afterTimestamp = prevOps[len(prevOps)-1].CreatedAt.Format(time.RFC3339Nano)
					log.Printf("  Using cursor from previous bundle file: %s", afterTimestamp)
				}
			}
		}
	}

	if afterTimestamp == "" && bundleNumber > 1 {
		return nil, fmt.Errorf("cannot determine cursor for bundle %06d (previous bundle not found)", bundleNumber)
	}

	operations, err := bm.fetchBundleFromPLC(ctx, plcClient, afterTimestamp)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch bundle from PLC: %w", err)
	}

	if len(operations) == 0 {
		return nil, fmt.Errorf("no operations returned for bundle %06d", bundleNumber)
	}

	// Save bundle locally with hash
	hash, err := bm.saveBundleFileWithHash(path, operations)
	if err != nil {
		log.Printf("Warning: failed to save bundle file: %v", err)
	}

	// Index in database with hash
	if err := bm.indexBundleWithHash(ctx, bundleNumber, operations, path, hash); err != nil {
		log.Printf("Warning: failed to index bundle: %v", err)
	}

	log.Printf("✓ Fetched and saved bundle %06d (%d operations, hash: %s)",
		bundleNumber, len(operations), hash[:16]+"...")

	return operations, nil
}

// saveBundleFileWithHash saves operations and returns the hash
func (bm *BundleManager) saveBundleFileWithHash(path string, operations []PLCOperation) (string, error) {
	// Convert to JSONL format
	var jsonlData []byte
	for _, op := range operations {
		lineJSON, err := json.Marshal(op)
		if err != nil {
			return "", fmt.Errorf("failed to marshal operation: %w", err)
		}
		jsonlData = append(jsonlData, lineJSON...)
		jsonlData = append(jsonlData, '\n')
	}

	// Compress
	compressed := bm.encoder.EncodeAll(jsonlData, nil)

	// Calculate hash of compressed data
	hash := bm.calculateHash(compressed)

	// Write to file
	if err := os.WriteFile(path, compressed, 0644); err != nil {
		return "", err
	}

	return hash, nil
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
	_, err := bm.saveBundleFileWithHash(path, operations)
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

		operations = append(operations, op)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading JSONL: %w", err)
	}

	return operations, nil
}

// indexBundleWithHash stores bundle metadata with hash
func (bm *BundleManager) indexBundleWithHash(ctx context.Context, bundleNumber int, operations []PLCOperation, path string, hash string) error {
	if len(operations) == 0 {
		return nil
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

	fileInfo, _ := os.Stat(path)
	fileSize := int64(0)
	if fileInfo != nil {
		fileSize = fileInfo.Size()
	}

	bundle := &storage.PLCBundle{
		BundleNumber:   bundleNumber, // This IS the primary key
		StartTime:      operations[0].CreatedAt,
		EndTime:        operations[len(operations)-1].CreatedAt,
		OperationCount: len(operations),
		DIDs:           dids,
		FilePath:       path,
		FileSize:       fileSize,
		Hash:           hash,
		Compressed:     true,
		CreatedAt:      time.Now(),
	}

	return bm.db.CreateBundle(ctx, bundle)
}

// indexBundle (keep for compatibility)
func (bm *BundleManager) indexBundle(ctx context.Context, bundleNumber int, operations []PLCOperation, path string) error {
	// Calculate hash from file
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	hash := bm.calculateHash(data)

	return bm.indexBundleWithHash(ctx, bundleNumber, operations, path, hash)
}

// CreateBundleFromMempool creates a bundle from mempool operations
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

	// Save bundle file with hash
	hash, err := bm.saveBundleFileWithHash(path, operations)
	if err != nil {
		return 0, err
	}

	// Index bundle with hash
	if err := bm.indexBundleWithHash(ctx, bundleNumber, operations, path, hash); err != nil {
		return 0, err
	}

	log.Printf("✓ Created bundle %06d from mempool (%d operations, hash: %s)",
		bundleNumber, len(operations), hash[:16]+"...")

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
