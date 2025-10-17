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

	// Create bundle directory if it doesn't exist
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create bundle dir: %w", err)
	}

	// Create zstd encoder with better compression
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBetterCompression))
	if err != nil {
		return nil, fmt.Errorf("failed to create zstd encoder: %w", err)
	}

	// Create zstd decoder
	decoder, err := zstd.NewReader(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create zstd decoder: %w", err)
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

// DiscoverAndIndexBundles scans the filesystem for bundle files and indexes them in the database
func (bm *BundleManager) DiscoverAndIndexBundles(ctx context.Context) error {
	if !bm.enabled {
		return nil
	}

	log.Println("Discovering bundle files...")

	// Get existing bundles from database
	existingBundles, err := bm.db.GetBundles(ctx, 10000)
	if err != nil {
		log.Printf("Warning: failed to get existing bundles: %v", err)
		existingBundles = []*storage.PLCBundle{}
	}

	// Create map of existing bundle paths
	existingPaths := make(map[string]bool)
	for _, bundle := range existingBundles {
		existingPaths[bundle.FilePath] = true
	}

	// Scan directory for .zst files
	pattern := filepath.Join(bm.dir, "*.zst")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("failed to scan bundle directory: %w", err)
	}

	if len(files) == 0 {
		log.Println("No bundle files found")
		return nil
	}

	log.Printf("Found %d bundle files", len(files))

	newBundles := 0
	for _, filePath := range files {
		// Skip if already indexed
		if existingPaths[filePath] {
			continue
		}

		// Load bundle to extract metadata
		operations, err := bm.loadBundleFromFile(filePath)
		if err != nil {
			log.Printf("Warning: failed to load bundle %s: %v", filepath.Base(filePath), err)
			continue
		}

		if len(operations) == 0 {
			log.Printf("Warning: empty bundle %s", filepath.Base(filePath))
			continue
		}

		// Get file size
		fileInfo, err := os.Stat(filePath)
		if err != nil {
			log.Printf("Warning: failed to stat bundle %s: %v", filepath.Base(filePath), err)
			continue
		}

		// Create bundle metadata
		bundle := &storage.PLCBundle{
			StartTime:      operations[0].CreatedAt,
			EndTime:        operations[len(operations)-1].CreatedAt,
			OperationCount: len(operations),
			FilePath:       filePath,
			FileSize:       fileInfo.Size(),
			Compressed:     true,
			CreatedAt:      fileInfo.ModTime(),
		}

		// Index in database
		if err := bm.db.CreateBundle(ctx, bundle); err != nil {
			log.Printf("Warning: failed to index bundle %s: %v", filepath.Base(filePath), err)
			continue
		}

		log.Printf("✓ Indexed bundle: %s (%s to %s, %d ops, %.2f MB)",
			filepath.Base(filePath),
			bundle.StartTime.Format("2006-01-02 15:04"),
			bundle.EndTime.Format("2006-01-02 15:04"),
			bundle.OperationCount,
			float64(bundle.FileSize)/1024/1024)

		newBundles++
	}

	if newBundles > 0 {
		log.Printf("Indexed %d new bundles", newBundles)
	} else {
		log.Println("All bundles already indexed")
	}

	return nil
}

// SaveBundle saves a complete bundle to disk and database
func (bm *BundleManager) SaveBundle(ctx context.Context, operations []PLCOperation, isComplete bool) error {
	if !bm.enabled || !isComplete {
		return nil
	}

	if len(operations) == 0 {
		return nil
	}

	startTime := operations[0].CreatedAt
	endTime := operations[len(operations)-1].CreatedAt

	// Generate filename based on start time
	filename := fmt.Sprintf("plc_bundle_%s.json.zst", startTime.Format("2006-01-02T15-04-05"))
	filePath := filepath.Join(bm.dir, filename)

	// Check if file already exists
	if _, err := os.Stat(filePath); err == nil {
		log.Printf("Bundle already exists: %s", filename)
		return nil
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(operations)
	if err != nil {
		return fmt.Errorf("failed to marshal operations: %w", err)
	}

	// Compress
	compressed := bm.encoder.EncodeAll(jsonData, nil)

	// Write to file
	if err := os.WriteFile(filePath, compressed, 0644); err != nil {
		return fmt.Errorf("failed to write bundle file: %w", err)
	}

	// Store metadata in database
	bundle := &storage.PLCBundle{
		StartTime:      startTime,
		EndTime:        endTime,
		OperationCount: len(operations),
		FilePath:       filePath,
		FileSize:       int64(len(compressed)),
		Compressed:     true,
		CreatedAt:      time.Now(),
	}

	if err := bm.db.CreateBundle(ctx, bundle); err != nil {
		return fmt.Errorf("failed to store bundle metadata: %w", err)
	}

	return nil
}

// FindBundle checks if a bundle exists for the given time (or next available)
func (bm *BundleManager) FindBundle(ctx context.Context, afterTimestamp string) (*storage.PLCBundle, error) {
	if !bm.enabled {
		return nil, nil
	}

	var afterTime time.Time

	if afterTimestamp == "" {
		// Start from beginning of time to get first bundle
		afterTime = time.Time{}
	} else {
		// Parse timestamp
		var parseErr error
		afterTime, parseErr = time.Parse(time.RFC3339Nano, afterTimestamp)
		if parseErr != nil {
			afterTime, parseErr = time.Parse(time.RFC3339, afterTimestamp)
			if parseErr != nil {
				return nil, nil // Can't parse, skip
			}
		}
	}

	// Get next bundle after this time (or first bundle if afterTime is zero)
	bundle, err := bm.db.GetBundle(ctx, afterTime)
	if err != nil || bundle == nil {
		return nil, nil // No bundle found
	}

	// Verify file exists
	if _, err := os.Stat(bundle.FilePath); err != nil {
		log.Printf("Warning: bundle file not found: %s", bundle.FilePath)
		return nil, nil
	}

	return bundle, nil
}

// LoadBundleFromFile loads operations from a bundle file
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

	// Unmarshal JSON
	var operations []PLCOperation
	if err := json.Unmarshal(decompressed, &operations); err != nil {
		return nil, fmt.Errorf("failed to unmarshal bundle: %w", err)
	}

	return operations, nil
}

// GetStats returns bundle statistics
func (bm *BundleManager) GetStats(ctx context.Context) (int64, int64, error) {
	if !bm.enabled {
		return 0, 0, nil
	}
	return bm.db.GetBundleStats(ctx)
}
