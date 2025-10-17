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
	client *Client
	db     storage.Database
	config config.PLCConfig
}

func NewScanner(db storage.Database, cfg config.PLCConfig) *Scanner {
	return &Scanner{
		client: NewClient(cfg.DirectoryURL),
		db:     db,
		config: cfg,
	}
}

func (s *Scanner) Scan(ctx context.Context) error {
	startTime := time.Now()
	log.Println("Starting PLC directory scan...")

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

	// Paginate through all operations
	for {
		select {
		case <-ctx.Done():
			log.Println("Scan interrupted by context cancellation")
			return ctx.Err()
		default:
		}

		// Fetch batch of operations with retry logic
		operations, err := s.fetchWithRetry(ctx, afterTimestamp, 3)
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

		// Reset error counter on success
		consecutiveErrors = 0

		if len(operations) == 0 {
			log.Println("No more operations to process")
			break
		}

		log.Printf("Processing batch of %d operations (after: %s)", len(operations), afterTimestamp)

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
			// Use the ISO 8601 formatted timestamp from createdAt
			latestTimestamp = lastOp.CreatedAt.Format(time.RFC3339Nano)

			// Update afterTimestamp for next iteration
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

		// Rate limiting between batches
		//time.Sleep(500 * time.Millisecond)
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

	return nil
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
		// Skip nullified operations
		if op.IsNullified() {
			continue
		}

		// Extract PDS endpoint from operation directly
		pdsEndpoint := s.extractPDSFromOperation(op)
		if pdsEndpoint == "" {
			continue
		}

		// Skip if we've already seen this PDS in current batch
		if seenInBatch[pdsEndpoint] {
			continue
		}
		seenInBatch[pdsEndpoint] = true

		// Check if PDS already exists in database
		exists, err := s.db.PDSExists(ctx, pdsEndpoint)
		if err != nil {
			log.Printf("Error checking PDS existence: %v", err)
			continue
		}

		if exists {
			continue // Already know about this PDS
		}

		// New PDS! Store it
		if err := s.db.UpsertPDS(ctx, &storage.PDS{
			Endpoint:     pdsEndpoint,
			DiscoveredAt: time.Now(),
			LastChecked:  time.Time{},
			Status:       "unknown",
		}); err != nil {
			log.Printf("Error storing new PDS %s: %v", pdsEndpoint, err)
			continue
		}

		log.Printf("✓ Discovered new PDS: %s (from DID %s)", pdsEndpoint, op.DID)
		newPDSCount++
	}

	return newPDSCount, nil
}

// Extract PDS endpoint directly from operation
func (s *Scanner) extractPDSFromOperation(op PLCOperation) string {
	// PLC operations have "services" as a map, not an array
	if services, ok := op.Operation["services"].(map[string]interface{}); ok {
		// Look for atproto_pds service
		if atprotoPDS, ok := services["atproto_pds"].(map[string]interface{}); ok {
			if endpoint, ok := atprotoPDS["endpoint"].(string); ok {
				// Validate it's actually a PDS endpoint
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
