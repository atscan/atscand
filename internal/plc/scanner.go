package plc

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/atscan/atscanner/internal/config"
	"github.com/atscan/atscanner/internal/storage"
)

type Scanner struct {
	client        *Client
	db            storage.Database
	config        config.PLCConfig
	bundleManager *BundleManager
}

func NewScanner(db storage.Database, cfg config.PLCConfig) *Scanner {
	bundleManager, err := NewBundleManager(cfg.CacheDir, cfg.UseCache, db)
	if err != nil {
		log.Printf("Warning: failed to initialize bundle manager: %v", err)
		bundleManager = &BundleManager{enabled: false}
	}

	return &Scanner{
		client:        NewClient(cfg.DirectoryURL),
		db:            db,
		config:        cfg,
		bundleManager: bundleManager,
	}
}

func (s *Scanner) Close() {
	if s.bundleManager != nil {
		s.bundleManager.Close()
	}
}

func (s *Scanner) Scan(ctx context.Context) error {
	startTime := time.Now()
	log.Println("Starting PLC directory scan...")
	log.Println("⚠ Note: PLC directory has rate limit of 500 requests per 5 minutes")

	cursor, err := s.db.GetScanCursor(ctx, "plc_directory")
	if err != nil {
		return fmt.Errorf("failed to get scan cursor: %w", err)
	}

	currentBundle := cursor.LastBundleNumber
	if currentBundle == 0 {
		currentBundle = 1
	} else {
		currentBundle++
	}

	log.Printf("Starting from bundle %06d", currentBundle) // Changed from %06x

	// Ensure bundle continuity (all previous bundles exist)
	if currentBundle > 1 {
		log.Printf("Checking bundle continuity...")
		if err := s.bundleManager.EnsureBundleContinuity(ctx, currentBundle); err != nil {
			return fmt.Errorf("bundle continuity check failed: %w", err)
		}
	}

	totalProcessed := int64(0)
	newPDSCount := int64(0)

	// Process bundles sequentially
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		log.Printf("→ Processing bundle %06d...", currentBundle)

		// Load bundle (lazy-loaded from file or PLC)
		operations, err := s.bundleManager.LoadBundle(ctx, currentBundle, s.client)
		if err != nil {
			log.Printf("Failed to load bundle %06x: %v", currentBundle, err)

			// If rate limited, wait longer before retrying
			if contains(err.Error(), "rate limited") {
				log.Println("⚠ Rate limit hit, pausing for 5 minutes...")
				time.Sleep(5 * time.Minute)
				continue // Retry same bundle
			}

			// Check if this is just end of data (not an error)
			if currentBundle > 1 {
				// Try to fetch with cursor from previous bundle
				log.Println("→ Checking if we've reached the end of available data...")

				// Get previous bundle to check timestamp
				prevBundle, err := s.db.GetBundleByNumber(ctx, currentBundle-1)
				if err == nil {
					// Try fetching with after timestamp
					afterTimestamp := prevBundle.EndTime.Format(time.RFC3339Nano)
					ops, err := s.client.Export(ctx, ExportOptions{
						Count: 1000,
						After: afterTimestamp,
					})

					if err == nil && len(ops) > 0 {
						// More data available, add to mempool
						log.Printf("→ Found %d operations, adding to mempool", len(ops))
						if err := s.addToMempool(ctx, ops); err != nil {
							log.Printf("Error adding to mempool: %v", err)
						}

						// Process mempool
						if err := s.processMempoolRecursive(ctx, &newPDSCount, &currentBundle, &totalProcessed); err != nil {
							log.Printf("Error processing mempool: %v", err)
						}
					}
				}
			}

			break // End of available data
		}

		// Check if this is a complete bundle
		isComplete := len(operations) == 1000

		if isComplete {
			// Process complete bundle
			batchNewPDS, err := s.processBatch(ctx, operations)
			if err != nil {
				log.Printf("Error processing bundle: %v", err)
			}

			newPDSCount += batchNewPDS
			totalProcessed += int64(len(operations))

			log.Printf("✓ Processed bundle %06d: %d operations, %d new PDS",
				currentBundle, len(operations), batchNewPDS)

			// Update cursor
			if err := s.db.UpdateScanCursor(ctx, &storage.ScanCursor{
				Source:           "plc_directory",
				LastBundleNumber: currentBundle,
				LastScanTime:     time.Now(),
				RecordsProcessed: cursor.RecordsProcessed + totalProcessed,
			}); err != nil {
				log.Printf("Warning: failed to update cursor: %v", err)
			}

			currentBundle++
		} else {
			// Incomplete bundle - add to mempool
			log.Printf("→ Bundle %06x incomplete (%d ops), adding to mempool", currentBundle, len(operations))

			if err := s.addToMempool(ctx, operations); err != nil {
				log.Printf("Error adding to mempool: %v", err)
			}

			// Process mempool
			if err := s.processMempoolRecursive(ctx, &newPDSCount, &currentBundle, &totalProcessed); err != nil {
				log.Printf("Error processing mempool: %v", err)
			}

			break // End of scan
		}

		// Rate limiting
		//time.Sleep(200 * time.Millisecond)
	}

	log.Printf("PLC scan completed: %d operations, %d new PDS servers in %v",
		totalProcessed, newPDSCount, time.Since(startTime))

	return nil
}

// addToMempool adds operations to mempool and processes them for PDS discovery
func (s *Scanner) addToMempool(ctx context.Context, operations []PLCOperation) error {
	mempoolOps := make([]storage.MempoolOperation, len(operations))

	for i, op := range operations {
		opJSON, _ := json.Marshal(op)
		mempoolOps[i] = storage.MempoolOperation{
			DID:       op.DID,
			Operation: string(opJSON),
			CID:       op.CID,
			CreatedAt: op.CreatedAt,
		}
	}

	// Add to mempool
	if err := s.db.AddToMempool(ctx, mempoolOps); err != nil {
		return err
	}

	// Process for PDS discovery immediately
	_, err := s.processBatch(ctx, operations)
	return err
}

// processMempoolRecursive checks mempool and creates bundles when >= 1000 ops
func (s *Scanner) processMempoolRecursive(ctx context.Context, newPDSCount *int64, currentBundle *int, totalProcessed *int64) error {
	for {
		// Check mempool size
		count, err := s.db.GetMempoolCount(ctx)
		if err != nil {
			return err
		}

		log.Printf("Mempool contains %d operations", count)

		if count < 1000 {
			log.Println("Mempool has < 1000 operations, waiting for more data")
			break
		}

		// Get first 1000 operations ordered by timestamp
		mempoolOps, err := s.db.GetMempoolOperations(ctx, 1000)
		if err != nil {
			return err
		}

		// Convert to PLCOperations
		operations := make([]PLCOperation, len(mempoolOps))
		mempoolIDs := make([]int64, len(mempoolOps))

		for i, mop := range mempoolOps {
			var op PLCOperation
			json.Unmarshal([]byte(mop.Operation), &op)
			operations[i] = op
			mempoolIDs[i] = mop.ID
		}

		// Create bundle from these operations
		bundleNum, err := s.bundleManager.CreateBundleFromMempool(ctx, operations)
		if err != nil {
			return err
		}

		// Remove from mempool
		if err := s.db.DeleteFromMempool(ctx, mempoolIDs); err != nil {
			return err
		}

		// Process for PDS (already processed when added, but for consistency)
		batchNewPDS, _ := s.processBatch(ctx, operations)
		*newPDSCount += batchNewPDS
		*totalProcessed += int64(len(operations))

		*currentBundle = bundleNum

		// Update cursor
		s.db.UpdateScanCursor(ctx, &storage.ScanCursor{
			Source:           "plc_directory",
			LastBundleNumber: bundleNum,
			LastScanTime:     time.Now(),
			RecordsProcessed: *totalProcessed,
		})

		log.Printf("✓ Created bundle %06x from mempool", bundleNum)
	}

	return nil
}

// processBatch processes operations for PDS discovery
func (s *Scanner) processBatch(ctx context.Context, operations []PLCOperation) (int64, error) {
	newPDSCount := int64(0)
	seenInBatch := make(map[string]*PLCOperation)

	for _, op := range operations {
		if op.IsNullified() {
			continue
		}

		pdsEndpoint := s.extractPDSFromOperation(op)
		if pdsEndpoint == "" {
			continue
		}

		if _, seen := seenInBatch[pdsEndpoint]; !seen {
			seenInBatch[pdsEndpoint] = &op
		}
	}

	for pdsEndpoint, firstOp := range seenInBatch {
		exists, err := s.db.PDSExists(ctx, pdsEndpoint)
		if err != nil || exists {
			continue
		}

		if err := s.db.UpsertPDS(ctx, &storage.PDS{
			Endpoint:     pdsEndpoint,
			DiscoveredAt: firstOp.CreatedAt,
			LastChecked:  time.Time{},
			Status:       storage.PDSStatusUnknown,
		}); err != nil {
			log.Printf("Error storing PDS %s: %v", pdsEndpoint, err)
			continue
		}

		log.Printf("✓ Discovered new PDS: %s", pdsEndpoint)
		newPDSCount++
	}

	return newPDSCount, nil
}

func (s *Scanner) extractPDSFromOperation(op PLCOperation) string {
	if services, ok := op.Operation["services"].(map[string]interface{}); ok {
		if atprotoPDS, ok := services["atproto_pds"].(map[string]interface{}); ok {
			if endpoint, ok := atprotoPDS["endpoint"].(string); ok {
				if svcType, ok := atprotoPDS["type"].(string); ok {
					if svcType == "AtprotoPersonalDataServer" {
						return endpoint
					}
				}
			}
		}
	}
	return ""
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr
}
