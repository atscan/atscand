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

	log.Info("Starting from bundle %06d", currentBundle)

	// Ensure bundle continuity (all previous bundles exist)
	if currentBundle > 1 {
		log.Info("Checking bundle continuity...")
		if err := s.bundleManager.EnsureBundleContinuity(ctx, currentBundle); err != nil {
			return fmt.Errorf("bundle continuity check failed: %w", err)
		}
	}

	totalProcessed := int64(0)
	newPDSCount := int64(0)

	// ✅ CHECK MEMPOOL FIRST - if it has data, continue filling it instead of fetching new bundle
	mempoolCount, err := s.db.GetMempoolCount(ctx)
	if err != nil {
		return err
	}

	if mempoolCount > 0 {
		log.Info("→ Mempool has %d operations, continuing to fill it before fetching new bundles", mempoolCount)

		// Fill mempool until we have 10,000
		if err := s.fillMempoolToSize(ctx, &newPDSCount, &totalProcessed); err != nil {
			log.Error("Error filling mempool: %v", err)
			return err
		}

		// Try to create bundles from mempool
		if err := s.processMempoolRecursive(ctx, &newPDSCount, &currentBundle, &totalProcessed); err != nil {
			log.Error("Error processing mempool: %v", err)
		}

		log.Info("PLC scan completed: %d operations, %d new PDS servers in %v",
			totalProcessed, newPDSCount, time.Since(startTime))
		return nil
	}

	// Process bundles sequentially (normal flow when mempool is empty)
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
			// Complete bundle
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

			// ✅ Now fill mempool to 10,000
			if err := s.fillMempoolToSize(ctx, &newPDSCount, &totalProcessed); err != nil {
				log.Error("Error filling mempool: %v", err)
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

func (s *Scanner) fillMempoolToSize(ctx context.Context, newPDSCount *int64, totalProcessed *int64) error {
	const fetchLimit = 1000 // PLC directory limit

	for {
		countBefore, err := s.db.GetMempoolCount(ctx)
		if err != nil {
			return err
		}

		if countBefore >= BUNDLE_SIZE {
			log.Info("✓ Mempool filled to %d operations (target: %d)", countBefore, BUNDLE_SIZE)
			return nil
		}

		log.Info("→ Mempool has %d/%d operations, fetching more from PLC directory...", countBefore, BUNDLE_SIZE)

		// ✅ Get just the last operation (much faster!)
		lastOp, err := s.db.GetLastMempoolOperation(ctx)
		if err != nil {
			return err
		}

		var afterTimestamp string
		if lastOp != nil {
			afterTimestamp = lastOp.CreatedAt.Format(time.RFC3339Nano)
			log.Verbose("  Using cursor: %s", afterTimestamp)
		}

		// ✅ Always fetch 1000 (PLC limit)
		operations, err := s.client.Export(ctx, ExportOptions{
			Count: fetchLimit,
			After: afterTimestamp,
		})
		if err != nil {
			return fmt.Errorf("failed to fetch from PLC: %w", err)
		}

		fetchedCount := len(operations)
		log.Verbose("  Fetched %d operations from PLC", fetchedCount)

		// ✅ No data at all - we're done
		if fetchedCount == 0 {
			log.Info("→ No more data available from PLC directory (mempool has %d/%d)", countBefore, BUNDLE_SIZE)
			return nil
		}

		// Add to mempool (with duplicate checking)
		if err := s.addToMempool(ctx, operations); err != nil {
			return err
		}

		*totalProcessed += int64(fetchedCount)

		// Check if mempool actually grew
		countAfter, err := s.db.GetMempoolCount(ctx)
		if err != nil {
			return err
		}

		newOpsAdded := countAfter - countBefore
		duplicateCount := fetchedCount - newOpsAdded

		log.Verbose("  Added %d new unique operations to mempool (%d were duplicates)",
			newOpsAdded, duplicateCount)

		// ✅ KEY LOGIC: Only repeat if we got a FULL batch (1000)
		// If < 1000, it means we've caught up to the latest data
		if fetchedCount < fetchLimit {
			log.Info("→ Received incomplete batch (%d/%d), caught up to latest data",
				fetchedCount, fetchLimit)
			log.Info("→ Stopping fill, mempool has %d/%d operations", countAfter, BUNDLE_SIZE)
			return nil
		}

		// Got full batch (1000), might be more data - continue loop
		log.Verbose("  Received full batch (%d), checking for more data...", fetchLimit)
	}
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
			log.Info("Mempool has %d/%d operations, cannot create bundle yet", count, BUNDLE_SIZE)
			break
		}

		log.Info("→ Creating bundle from mempool (%d operations available)...", count)

		// Get first BUNDLE_SIZE operations ordered by timestamp
		mempoolOps, err := s.db.GetMempoolOperations(ctx, BUNDLE_SIZE)
		if err != nil {
			return err
		}

		// Convert to PLCOperations and track IDs
		operations := make([]PLCOperation, 0, BUNDLE_SIZE)
		mempoolIDs := make([]int64, 0, BUNDLE_SIZE)
		seenCIDs := make(map[string]bool)

		for _, mop := range mempoolOps {
			// ✅ Skip duplicates (shouldn't happen but safety check)
			if seenCIDs[mop.CID] {
				mempoolIDs = append(mempoolIDs, mop.ID) // Still delete it
				continue
			}
			seenCIDs[mop.CID] = true

			var op PLCOperation
			json.Unmarshal([]byte(mop.Operation), &op)
			operations = append(operations, op)
			mempoolIDs = append(mempoolIDs, mop.ID)

			if len(operations) >= BUNDLE_SIZE {
				break
			}
		}

		// Final check
		if len(operations) < BUNDLE_SIZE {
			log.Error("⚠ Only got %d unique operations from mempool, need %d", len(operations), BUNDLE_SIZE)
			break
		}

		// Create bundle from these operations
		bundleNum, err := s.bundleManager.CreateBundleFromMempool(ctx, operations)
		if err != nil {
			return err
		}

		// Remove from mempool (only what we used)
		if err := s.db.DeleteFromMempool(ctx, mempoolIDs[:len(operations)]); err != nil {
			return err
		}

		// Process for PDS
		batchNewPDS, _ := s.processBatch(ctx, operations)
		*newPDSCount += batchNewPDS

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
