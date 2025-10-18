package plc

import (
	"context"
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

// GetBundleFilename returns filename for bundle number (6-char hex)
func (bm *BundleManager) GetBundleFilename(bundleNumber int) string {
	return fmt.Sprintf("%06x.json.zst", bundleNumber)
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
func (bm *BundleManager) LoadBundle(ctx context.Context, bundleNumber int, plcClient *Client) ([]PLCOperation, error) {
	if !bm.enabled {
		return nil, fmt.Errorf("bundle manager disabled")
	}

	path := bm.GetBundlePath(bundleNumber)

	// Try to load from local file first
	if bm.BundleExists(bundleNumber) {
		log.Printf("→ Loading bundle %06x from local file", bundleNumber)
		return bm.loadBundleFromFile(path)
	}

	// Bundle doesn't exist locally - fetch from PLC directory
	log.Printf("→ Bundle %06x not found locally, fetching from PLC directory...", bundleNumber)

	// Get the cursor timestamp from previous bundle
	var afterTimestamp string

	if bundleNumber > 1 {
		// Try to get previous bundle from database
		prevBundle, err := bm.db.GetBundleByNumber(ctx, bundleNumber-1)
		if err == nil && prevBundle != nil {
			// Use end timestamp from previous bundle
			afterTimestamp = prevBundle.EndTime.Format(time.RFC3339Nano)
			log.Printf("  Using cursor from bundle %06x: %s", bundleNumber-1, afterTimestamp)
		} else {
			// Previous bundle not in database, try to load from file
			if bm.BundleExists(bundleNumber - 1) {
				prevOps, err := bm.loadBundleFromFile(bm.GetBundlePath(bundleNumber - 1))
				if err == nil && len(prevOps) > 0 {
					afterTimestamp = prevOps[len(prevOps)-1].CreatedAt.Format(time.RFC3339Nano)
					log.Printf("  Using cursor from previous bundle file: %s", afterTimestamp)
				}
			}
		}
	}

	// If still no timestamp (bundle 1 or couldn't get previous), start from beginning
	if afterTimestamp == "" && bundleNumber > 1 {
		return nil, fmt.Errorf("cannot determine cursor for bundle %06x (previous bundle not found)", bundleNumber)
	}

	operations, err := bm.fetchBundleFromPLC(ctx, plcClient, afterTimestamp)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch bundle from PLC: %w", err)
	}

	if len(operations) == 0 {
		return nil, fmt.Errorf("no operations returned for bundle %06x", bundleNumber)
	}

	// Save bundle locally
	if err := bm.saveBundleFile(path, operations); err != nil {
		log.Printf("Warning: failed to save bundle file: %v", err)
	}

	// Index in database
	if err := bm.indexBundle(ctx, bundleNumber, operations, path); err != nil {
		log.Printf("Warning: failed to index bundle: %v", err)
	}

	log.Printf("✓ Fetched and saved bundle %06x (%d operations, %s to %s)",
		bundleNumber, len(operations),
		operations[0].CreatedAt.Format("2006-01-02 15:04"),
		operations[len(operations)-1].CreatedAt.Format("2006-01-02 15:04"))

	return operations, nil
}

// fetchBundleFromPLC fetches operations from PLC directory using datetime cursor
func (bm *BundleManager) fetchBundleFromPLC(ctx context.Context, client *Client, afterTimestamp string) ([]PLCOperation, error) {
	// Fetch next batch of 1000 operations after the given timestamp
	return client.Export(ctx, ExportOptions{
		Count: 1000,
		After: afterTimestamp, // ISO 8601 datetime from previous bundle
	})
}

// saveBundleFile saves operations to a bundle file
func (bm *BundleManager) saveBundleFile(path string, operations []PLCOperation) error {
	jsonData, err := json.Marshal(operations)
	if err != nil {
		return err
	}

	compressed := bm.encoder.EncodeAll(jsonData, nil)

	return os.WriteFile(path, compressed, 0644)
}

// loadBundleFromFile loads operations from bundle file
func (bm *BundleManager) loadBundleFromFile(path string) ([]PLCOperation, error) {
	compressedData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	decompressed, err := bm.decoder.DecodeAll(compressedData, nil)
	if err != nil {
		return nil, err
	}

	var operations []PLCOperation
	if err := json.Unmarshal(decompressed, &operations); err != nil {
		return nil, err
	}

	return operations, nil
}

// indexBundle stores bundle metadata in database
func (bm *BundleManager) indexBundle(ctx context.Context, bundleNumber int, operations []PLCOperation, path string) error {
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
		BundleNumber:   bundleNumber,
		StartTime:      operations[0].CreatedAt,
		EndTime:        operations[len(operations)-1].CreatedAt,
		OperationCount: len(operations),
		DIDs:           dids,
		FilePath:       path,
		FileSize:       fileSize,
		Compressed:     true,
		CreatedAt:      time.Now(),
	}

	return bm.db.CreateBundle(ctx, bundle)
}

// CreateBundleFromMempool creates a bundle from mempool operations
func (bm *BundleManager) CreateBundleFromMempool(ctx context.Context, operations []PLCOperation) (int, error) {
	if !bm.enabled {
		return 0, fmt.Errorf("bundle manager disabled")
	}

	if len(operations) != 1000 {
		return 0, fmt.Errorf("bundle must have exactly 1000 operations, got %d", len(operations))
	}

	// Get next bundle number
	lastBundle, err := bm.db.GetLastBundleNumber(ctx)
	if err != nil {
		return 0, err
	}
	bundleNumber := lastBundle + 1

	path := bm.GetBundlePath(bundleNumber)

	// Save bundle file
	if err := bm.saveBundleFile(path, operations); err != nil {
		return 0, err
	}

	// Index bundle
	if err := bm.indexBundle(ctx, bundleNumber, operations, path); err != nil {
		return 0, err
	}

	log.Printf("✓ Created bundle %06x from mempool (%d operations)", bundleNumber, len(operations))

	return bundleNumber, nil
}

// GetStats returns bundle statistics
func (bm *BundleManager) GetStats(ctx context.Context) (int64, int64, error) {
	if !bm.enabled {
		return 0, 0, nil
	}
	return bm.db.GetBundleStats(ctx)
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
				return fmt.Errorf("bundle %06x is missing (required for continuity)", i)
			}
		}
	}

	return nil
}
