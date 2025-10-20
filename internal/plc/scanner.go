package plc

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/acarl005/stripansi"
	"github.com/atscan/atscanner/internal/config"
	"github.com/atscan/atscanner/internal/log"
	"github.com/atscan/atscanner/internal/storage"
)

type Scanner struct {
	client        *Client
	db            storage.Database
	config        config.PLCConfig
	bundleManager *BundleManager
}

func NewScanner(db storage.Database, cfg config.PLCConfig) *Scanner {
	bundleManager, err := NewBundleManager(cfg.BundleDir, cfg.UseCache, db)
	if err != nil {
		log.Error("Warning: failed to initialize bundle manager: %v", err)
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
	log.Info("Starting PLC directory scan...")
	log.Info("⚠ Note: PLC directory has rate limit of 500 requests per 5 minutes")

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

	log.Info("Starting from bundle %06d", currentBundle) // Changed from %06x

	// Ensure bundle continuity (all previous bundles exist)
	if currentBundle > 1 {
		log.Info("Checking bundle continuity...")
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

		log.Verbose("→ Processing bundle %06d...", currentBundle)

		// Load bundle (returns operations, isComplete flag, and error)
		operations, isComplete, err := s.bundleManager.LoadBundle(ctx, currentBundle, s.client)
		if err != nil {
			log.Error("Failed to load bundle %06d: %v", currentBundle, err)

			// If rate limited, wait and retry
			if contains(err.Error(), "rate limited") {
				log.Info("⚠ Rate limit hit, pausing for 5 minutes...")
				time.Sleep(5 * time.Minute)
				continue
			}

			// Check if this is just end of data
			if currentBundle > 1 {
				log.Info("→ Reached end of available data")
				// Try mempool processing
				if err := s.processMempoolRecursive(ctx, &newPDSCount, &currentBundle, &totalProcessed); err != nil {
					log.Error("Error processing mempool: %v", err)
				}
			}
			break
		}

		if isComplete {
			// Complete bundle (1000 operations fetched, even if some were duplicates)
			batchNewPDS, err := s.processBatch(ctx, operations)
			if err != nil {
				log.Error("Error processing bundle: %v", err)
			}

			newPDSCount += batchNewPDS
			totalProcessed += int64(len(operations))

			log.Verbose("✓ Processed bundle %06d: %d operations (after dedup), %d new PDS",
				currentBundle, len(operations), batchNewPDS)

			// Update cursor
			if err := s.db.UpdateScanCursor(ctx, &storage.ScanCursor{
				Source:           "plc_directory",
				LastBundleNumber: currentBundle,
				LastScanTime:     time.Now(),
				RecordsProcessed: cursor.RecordsProcessed + totalProcessed,
			}); err != nil {
				log.Error("Warning: failed to update cursor: %v", err)
			}

			currentBundle++
		} else {
			// Incomplete bundle - we've reached the end of available data
			log.Info("→ Bundle %06d incomplete (%d ops), adding to mempool", currentBundle, len(operations))

			if err := s.addToMempool(ctx, operations); err != nil {
				log.Error("Error adding to mempool: %v", err)
			}

			// Process mempool
			if err := s.processMempoolRecursive(ctx, &newPDSCount, &currentBundle, &totalProcessed); err != nil {
				log.Error("Error processing mempool: %v", err)
			}

			break // End of scan
		}
	}

	log.Info("PLC scan completed: %d operations, %d new PDS servers in %v",
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

		log.Verbose("Mempool contains %d operations", count)

		if count < BUNDLE_SIZE {
			log.Info("Mempool has < %d operations, waiting for more data", BUNDLE_SIZE)
			break
		}

		// ✅ Fetch MORE than needed to account for potential duplicates during dedup
		// Fetch 1.2x to have buffer (20% extra)
		fetchSize := int(float64(BUNDLE_SIZE) * 1.2)
		if fetchSize > count {
			fetchSize = count
		}

		mempoolOps, err := s.db.GetMempoolOperations(ctx, fetchSize)
		if err != nil {
			return err
		}

		// ✅ Deduplicate by CID while preserving order
		seenCIDs := make(map[string]bool)
		var uniqueOps []PLCOperation
		mempoolIDs := make([]int64, 0, len(mempoolOps))

		for _, mop := range mempoolOps {
			if seenCIDs[mop.CID] {
				// Duplicate - still mark for deletion from mempool
				mempoolIDs = append(mempoolIDs, mop.ID)
				continue
			}

			seenCIDs[mop.CID] = true

			var op PLCOperation
			json.Unmarshal([]byte(mop.Operation), &op)
			uniqueOps = append(uniqueOps, op)
			mempoolIDs = append(mempoolIDs, mop.ID)

			// Stop when we have enough unique operations
			if len(uniqueOps) >= BUNDLE_SIZE {
				break
			}
		}

		// ✅ Check if we have enough unique operations
		if len(uniqueOps) < BUNDLE_SIZE {
			log.Info("Mempool has only %d unique operations after dedup (need %d), waiting for more data",
				len(uniqueOps), BUNDLE_SIZE)
			break
		}

		// Trim to exact size
		operations := uniqueOps[:BUNDLE_SIZE]
		idsToDelete := mempoolIDs[:len(operations)]

		// Create bundle from these operations
		bundleNum, err := s.bundleManager.CreateBundleFromMempool(ctx, operations)
		if err != nil {
			return err
		}

		// Remove from mempool (only the ones we used)
		if err := s.db.DeleteFromMempool(ctx, idsToDelete); err != nil {
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

		log.Info("✓ Created bundle %06d from mempool", bundleNum)
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
			log.Error("Error storing PDS %s: %v", stripansi.Strip(pdsEndpoint), err)
			continue
		}

		log.Info("✓ Discovered new PDS: %s", stripansi.Strip(pdsEndpoint))
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
