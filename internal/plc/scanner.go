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
	client *Client
	db     storage.Database
	config config.PLCConfig
	cache  *Cache
}

func NewScanner(db storage.Database, cfg config.PLCConfig) *Scanner {
	cache, err := NewCache(cfg.CacheDir, cfg.UseCache)
	if err != nil {
		log.Printf("Warning: failed to initialize cache: %v", err)
		cache = &Cache{enabled: false}
	}

	return &Scanner{
		client: NewClient(cfg.DirectoryURL),
		db:     db,
		config: cfg,
		cache:  cache,
	}
}

func (s *Scanner) Close() {
	if s.cache != nil {
		s.cache.Close()
	}
}

func (s *Scanner) Scan(ctx context.Context) error {
	startTime := time.Now()
	log.Println("Starting PLC directory scan...")

	// Print cache stats
	if s.config.UseCache {
		count, size, _ := s.cache.Stats()
		log.Printf("Cache: %d files, %.2f MB", count, float64(size)/1024/1024)
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
		log.Println("Starting fresh scan (no previous cursor)")
	}

	metrics := &storage.PLCMetrics{
		LastScanTime: startTime,
	}

	totalProcessed := int64(0)
	newPDSCount := int64(0)
	latestTimestamp := afterTimestamp
	consecutiveErrors := 0
	maxConsecutiveErrors := 3
	cacheHits := 0
	cacheMisses := 0

	// Paginate through all operations
	for {
		select {
		case <-ctx.Done():
			log.Println("Scan interrupted by context cancellation")
			return ctx.Err()
		default:
		}

		// Fetch batch of operations (with cache)
		operations, fromCache, err := s.fetchBatchWithCache(ctx, afterTimestamp, 3)
		if err != nil {
			metrics.ErrorCount++
			consecutiveErrors++

			log.Printf("Error fetching operations (attempt %d/%d): %v",
				consecutiveErrors, maxConsecutiveErrors, err)

			if consecutiveErrors >= maxConsecutiveErrors {
				return fmt.Errorf("failed after %d consecutive errors: %w", maxConsecutiveErrors, err)
			}

			// Exponential backoff
			backoff := time.Duration(consecutiveErrors) * 5 * time.Second
			log.Printf("Backing off for %v before retry...", backoff)
			time.Sleep(backoff)
			continue
		}

		// Track cache performance
		if fromCache {
			cacheHits++
		} else {
			cacheMisses++
		}

		// Reset error counter on success
		consecutiveErrors = 0

		if len(operations) == 0 {
			log.Println("No more operations to process")
			break
		}

		cacheStatus := ""
		if fromCache {
			cacheStatus = " [cached]"
		}
		log.Printf("Processing batch of %d operations (after: %s)%s", len(operations), afterTimestamp, cacheStatus)

		// DEBUG: Print first operation structure (only once)
		if len(operations) > 0 && totalProcessed == 0 {
			log.Println("=== DEBUG: First operation structure ===")
			opJSON, _ := json.MarshalIndent(operations[0], "", "  ")
			log.Printf("%s\n", string(opJSON))
		}

		// Process this batch
		batchNewPDS, err := s.processBatch(ctx, operations)
		if err != nil {
			log.Printf("Error processing batch: %v", err)
			metrics.ErrorCount++
		}

		newPDSCount += batchNewPDS
		totalProcessed += int64(len(operations))

		// Update timestamp to the latest operation's createdAt
		if len(operations) > 0 {
			lastOp := operations[len(operations)-1]
			latestTimestamp = lastOp.CreatedAt.Format(time.RFC3339Nano)
			afterTimestamp = latestTimestamp

			// Save cursor position periodically (every batch)
			if err := s.db.UpdateScanCursor(ctx, &storage.ScanCursor{
				Source:           "plc_directory",
				LastTimestamp:    latestTimestamp,
				LastScanTime:     time.Now(),
				RecordsProcessed: cursor.RecordsProcessed + totalProcessed,
			}); err != nil {
				log.Printf("Warning: failed to update cursor: %v", err)
			}
		}

		// Check if we got fewer results than requested (end of stream)
		if len(operations) < s.config.BatchSize {
			log.Println("Reached end of PLC export")
			break
		}

		// Rate limiting between batches (only if not using cache)
		if !fromCache {
			time.Sleep(500 * time.Millisecond)
		}
	}

	// Final cursor update
	if latestTimestamp != cursor.LastTimestamp && latestTimestamp != "" {
		if err := s.db.UpdateScanCursor(ctx, &storage.ScanCursor{
			Source:           "plc_directory",
			LastTimestamp:    latestTimestamp,
			LastScanTime:     time.Now(),
			RecordsProcessed: cursor.RecordsProcessed + totalProcessed,
		}); err != nil {
			log.Printf("Warning: failed to update final cursor: %v", err)
		}
	}

	// Final metrics
	metrics.TotalDIDs = totalProcessed
	metrics.TotalPDS = newPDSCount
	metrics.UniquePDS = newPDSCount
	metrics.ScanDuration = time.Since(startTime).Milliseconds()

	// Store metrics
	if err := s.db.StorePLCMetrics(ctx, metrics); err != nil {
		log.Printf("Error storing metrics: %v", err)
	}

	log.Printf("PLC scan completed: %d operations processed, %d new PDS servers found in %v",
		totalProcessed, newPDSCount, time.Since(startTime))
	log.Printf("Cache performance: %d hits, %d misses (%.1f%% hit rate)",
		cacheHits, cacheMisses, float64(cacheHits)*100/float64(cacheHits+cacheMisses))

	return nil
}

// fetchBatchWithCache fetches operations with caching support
func (s *Scanner) fetchBatchWithCache(ctx context.Context, afterTimestamp string, maxRetries int) ([]PLCOperation, bool, error) {
	// Check cache first
	if s.cache.Has(afterTimestamp) {
		log.Printf("→ Using cached batch for after=%s", afterTimestamp)
		operations, err := s.cache.Get(afterTimestamp)
		if err != nil {
			log.Printf("Warning: cache read failed, falling back to API: %v", err)
		} else {
			return operations, true, nil
		}
	}

	// Fetch from API with retry
	operations, err := s.fetchWithRetry(ctx, afterTimestamp, maxRetries)
	if err != nil {
		return nil, false, err
	}

	// Store in cache
	if err := s.cache.Set(afterTimestamp, operations); err != nil {
		log.Printf("Warning: failed to cache batch: %v", err)
	} else {
		log.Printf("✓ Cached batch to %s", s.cache.GetCachePath(afterTimestamp))
	}

	return operations, false, nil
}

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
	seenInBatch := make(map[string]bool)

	for _, op := range operations {
		if op.IsNullified() {
			continue
		}

		pdsEndpoint := s.extractPDSFromOperation(op)
		if pdsEndpoint == "" {
			continue
		}

		if seenInBatch[pdsEndpoint] {
			continue
		}
		seenInBatch[pdsEndpoint] = true

		exists, err := s.db.PDSExists(ctx, pdsEndpoint)
		if err != nil {
			log.Printf("Error checking PDS existence: %v", err)
			continue
		}

		if exists {
			continue
		}

		if err := s.db.UpsertPDS(ctx, &storage.PDS{
			Endpoint:     pdsEndpoint,
			DiscoveredAt: time.Now(),
			LastChecked:  time.Time{},
			Status:       "unknown",
		}); err != nil {
			log.Printf("Error storing new PDS %s: %v", pdsEndpoint, err)
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
