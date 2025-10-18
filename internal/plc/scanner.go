package plc

import (
	"context"
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

	// Auto-discover bundles if using cache
	if s.config.UseCache {
		if err := s.bundleManager.DiscoverAndIndexBundles(ctx); err != nil {
			log.Printf("Warning: bundle discovery failed: %v", err)
		}
	}

	// Print bundle stats
	if s.config.UseCache {
		count, size, _ := s.bundleManager.GetStats(ctx)
		if count > 0 {
			log.Printf("Bundles available: %d files, %.2f MB total", count, float64(size)/1024/1024)
		} else {
			log.Println("No bundles available (will fetch from API)")
		}
	}

	// Get last cursor position
	cursor, err := s.db.GetScanCursor(ctx, "plc_directory")
	if err != nil {
		return fmt.Errorf("failed to get scan cursor: %w", err)
	}

	afterTimestamp := cursor.LastTimestamp

	if afterTimestamp != "" {
		log.Printf("Resuming from timestamp: %s", afterTimestamp)
	} else {
		log.Println("Starting fresh scan")
	}
	metrics := &storage.PLCMetrics{
		LastScanTime: startTime,
	}

	totalProcessed := int64(0)
	newPDSCount := int64(0)
	latestTimestamp := afterTimestamp
	consecutiveErrors := 0
	maxConsecutiveErrors := 3
	bundlesUsed := 0
	apiFetches := 0

	// Rest of the scanning logic stays the same...
	for {
		select {
		case <-ctx.Done():
			log.Println("Scan interrupted by context cancellation")
			return ctx.Err()
		default:
		}

		// Try to find a bundle first
		var operations []PLCOperation
		var fromBundle bool

		bundle, err := s.bundleManager.FindBundle(ctx, afterTimestamp)
		if err == nil && bundle != nil {
			log.Printf("→ Using bundle: %s to %s (%d ops, %.2f MB)",
				bundle.StartTime.Format("2006-01-02 15:04"),
				bundle.EndTime.Format("2006-01-02 15:04"),
				bundle.OperationCount,
				float64(bundle.FileSize)/1024/1024)

			ops, err := s.bundleManager.loadBundleFromFile(bundle.FilePath)
			if err != nil {
				log.Printf("Warning: failed to load bundle, falling back to API: %v", err)
			} else {
				operations = ops
				fromBundle = true
				bundlesUsed++

				// Jump to end of this bundle for next iteration
				afterTimestamp = bundle.EndTime.Format(time.RFC3339Nano)
			}
		}

		// Fetch from API if no bundle
		if !fromBundle {
			ops, err := s.fetchWithRetry(ctx, afterTimestamp, 3)
			if err != nil {
				metrics.ErrorCount++
				consecutiveErrors++

				log.Printf("Error fetching operations (attempt %d/%d): %v",
					consecutiveErrors, maxConsecutiveErrors, err)

				if consecutiveErrors >= maxConsecutiveErrors {
					return fmt.Errorf("failed after %d consecutive errors: %w", maxConsecutiveErrors, err)
				}

				backoff := time.Duration(consecutiveErrors) * 5 * time.Second
				log.Printf("Backing off for %v before retry...", backoff)
				time.Sleep(backoff)
				continue
			}
			operations = ops
			apiFetches++
		}

		consecutiveErrors = 0

		if len(operations) == 0 {
			log.Println("No more operations to process")
			break
		}

		bundleStatus := ""
		if fromBundle {
			bundleStatus = " [bundled]"
		}
		log.Printf("Processing batch of %d operations%s", len(operations), bundleStatus)

		// Process this batch
		batchNewPDS, err := s.processBatch(ctx, operations)
		if err != nil {
			log.Printf("Error processing batch: %v", err)
			metrics.ErrorCount++
		}

		newPDSCount += batchNewPDS
		totalProcessed += int64(len(operations))

		// Save as bundle if complete batch and not from bundle
		isCompleteBundle := len(operations) == s.config.BatchSize
		if !fromBundle && isCompleteBundle {
			if err := s.bundleManager.SaveBundle(ctx, operations, true); err != nil {
				log.Printf("Warning: failed to save bundle: %v", err)
			} else {
				log.Printf("✓ Saved bundle (%d operations)", len(operations))
			}
		}

		// Update timestamp to latest operation
		if len(operations) > 0 && !fromBundle {
			lastOp := operations[len(operations)-1]
			latestTimestamp = lastOp.CreatedAt.Format(time.RFC3339Nano)
			afterTimestamp = latestTimestamp
		}

		// Save cursor
		if latestTimestamp != "" {
			if err := s.db.UpdateScanCursor(ctx, &storage.ScanCursor{
				Source:           "plc_directory",
				LastTimestamp:    latestTimestamp,
				LastScanTime:     time.Now(),
				RecordsProcessed: cursor.RecordsProcessed + totalProcessed,
			}); err != nil {
				log.Printf("Warning: failed to update cursor: %v", err)
			}
		}

		// Check if end of stream
		if !fromBundle && len(operations) < s.config.BatchSize {
			log.Println("Reached end of PLC export (partial batch)")
			break
		}

		// Rate limiting (only for API fetches)
		if !fromBundle {
			time.Sleep(500 * time.Millisecond)
		}
	}

	// Final cursor update and metrics (same as before)
	if latestTimestamp != cursor.LastTimestamp && latestTimestamp != "" {
		s.db.UpdateScanCursor(ctx, &storage.ScanCursor{
			Source:           "plc_directory",
			LastTimestamp:    latestTimestamp,
			LastScanTime:     time.Now(),
			RecordsProcessed: cursor.RecordsProcessed + totalProcessed,
		})
	}

	metrics.TotalDIDs = totalProcessed
	metrics.TotalPDS = newPDSCount
	metrics.UniquePDS = newPDSCount
	metrics.ScanDuration = time.Since(startTime).Milliseconds()

	s.db.StorePLCMetrics(ctx, metrics)

	log.Printf("PLC scan completed: %d operations, %d new PDS servers in %v",
		totalProcessed, newPDSCount, time.Since(startTime))
	log.Printf("Source: %d bundles, %d API fetches", bundlesUsed, apiFetches)

	return nil
}

// ... rest of scanner methods stay the same

func (s *Scanner) fetchWithRetry(ctx context.Context, afterTimestamp string, maxRetries int) ([]PLCOperation, error) {
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		operations, err := s.client.Export(ctx, ExportOptions{
			Count: s.config.BatchSize,
			After: afterTimestamp,
		})

		if err == nil {
			return operations, nil
		}

		lastErr = err

		if attempt < maxRetries {
			backoff := time.Duration(attempt) * 2 * time.Second
			log.Printf("Fetch attempt %d/%d failed: %v, retrying in %v...",
				attempt, maxRetries, err, backoff)
			time.Sleep(backoff)
		}
	}

	return nil, fmt.Errorf("all retry attempts failed: %w", lastErr)
}

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
		if err != nil {
			continue
		}

		if exists {
			continue
		}

		// New PDS! Use storage.PDSStatusUnknown constant
		if err := s.db.UpsertPDS(ctx, &storage.PDS{
			Endpoint:     pdsEndpoint,
			DiscoveredAt: firstOp.CreatedAt,
			LastChecked:  time.Time{},
			Status:       storage.PDSStatusUnknown, // FIX: Use integer constant
		}); err != nil {
			log.Printf("Error storing PDS %s: %v", pdsEndpoint, err)
			continue
		}

		log.Printf("✓ Discovered new PDS: %s (first seen: %s)",
			pdsEndpoint, firstOp.CreatedAt.Format("2006-01-02 15:04"))
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
