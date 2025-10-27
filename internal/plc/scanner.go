package plc

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/atscan/atscanner/internal/config"
	"github.com/atscan/atscanner/internal/log"
	"github.com/atscan/atscanner/internal/storage"
)

type Scanner struct {
	bundleManager *BundleManager
	db            storage.Database
	config        config.PLCConfig
}

func NewScanner(db storage.Database, cfg config.PLCConfig) *Scanner {
	log.Verbose("NewScanner: IndexDIDs config = %v", cfg.IndexDIDs)

	bundleManager, err := NewBundleManager(cfg.BundleDir, cfg.DirectoryURL, db, cfg.IndexDIDs)
	if err != nil {
		log.Error("Failed to initialize bundle manager: %v", err)
		return nil
	}

	return &Scanner{
		bundleManager: bundleManager,
		db:            db,
		config:        cfg,
	}
}

func (s *Scanner) Close() {
	if s.bundleManager != nil {
		s.bundleManager.Close()
	}
}

func (s *Scanner) Scan(ctx context.Context) error {
	log.Info("Starting PLC directory scan...")

	cursor, err := s.db.GetScanCursor(ctx, "plc_directory")
	if err != nil {
		return fmt.Errorf("failed to get scan cursor: %w", err)
	}

	metrics := newMetrics(cursor.LastBundleNumber + 1)

	// Main processing loop
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		// Fetch and save bundle (library handles mempool internally)
		bundle, err := s.bundleManager.FetchAndSaveBundle(ctx)
		if err != nil {
			if isInsufficientOpsError(err) {
				// Show mempool status
				stats := s.bundleManager.libManager.GetMempoolStats()
				mempoolCount := stats["count"].(int)

				if mempoolCount > 0 {
					log.Info("→ Waiting for more operations (mempool has %d/%d ops)",
						mempoolCount, BUNDLE_SIZE)
				} else {
					log.Info("→ Caught up! No operations available")
				}
				break
			}

			if strings.Contains(err.Error(), "rate limited") {
				log.Info("⚠ Rate limited, pausing for 5 minutes...")
				time.Sleep(5 * time.Minute)
				continue
			}

			return fmt.Errorf("failed to fetch bundle: %w", err)
		}

		// Process operations for endpoint discovery
		counts, err := s.processBatch(ctx, bundle.Operations)
		if err != nil {
			log.Error("Failed to process batch: %v", err)
			// Continue anyway
		}

		// Update metrics
		s.mergeCounts(metrics.endpointCounts, counts)
		metrics.totalProcessed += int64(len(bundle.Operations))
		metrics.newEndpoints += sumCounts(counts)
		metrics.currentBundle = bundle.BundleNumber

		log.Info("✓ Processed bundle %06d: %d operations, %d new endpoints",
			bundle.BundleNumber, len(bundle.Operations), sumCounts(counts))

		// Update cursor
		if err := s.updateCursorForBundle(ctx, bundle.BundleNumber, metrics.totalProcessed); err != nil {
			log.Error("Warning: failed to update cursor: %v", err)
		}
	}

	// Show final mempool status
	stats := s.bundleManager.libManager.GetMempoolStats()
	if count, ok := stats["count"].(int); ok && count > 0 {
		log.Info("Mempool contains %d operations (%.1f%% of next bundle)",
			count, float64(count)/float64(BUNDLE_SIZE)*100)
	}

	metrics.logSummary()
	return nil
}

// processBatch extracts endpoints from operations
func (s *Scanner) processBatch(ctx context.Context, ops []PLCOperation) (map[string]int64, error) {
	counts := make(map[string]int64)
	seen := make(map[string]*PLCOperation)

	// Collect unique endpoints
	for i := range ops {
		op := &ops[i]

		if op.IsNullified() {
			continue
		}

		for _, ep := range s.extractEndpointsFromOperation(*op) {
			key := fmt.Sprintf("%s:%s", ep.Type, ep.Endpoint)
			if _, exists := seen[key]; !exists {
				seen[key] = op
			}
		}
	}

	// Store new endpoints
	for key, firstOp := range seen {
		parts := strings.SplitN(key, ":", 2)
		epType, endpoint := parts[0], parts[1]

		exists, err := s.db.EndpointExists(ctx, endpoint, epType)
		if err != nil || exists {
			continue
		}

		if err := s.storeEndpoint(ctx, epType, endpoint, firstOp.CreatedAt); err != nil {
			log.Error("Error storing %s endpoint %s: %v", epType, endpoint, err)
			continue
		}

		log.Info("✓ Discovered new %s endpoint: %s", epType, endpoint)
		counts[epType]++
	}

	return counts, nil
}

func (s *Scanner) extractEndpointsFromOperation(op PLCOperation) []EndpointInfo {
	var endpoints []EndpointInfo

	services, ok := op.Operation["services"].(map[string]interface{})
	if !ok {
		return endpoints
	}

	// Extract PDS
	if ep := s.extractServiceEndpoint(services, "atproto_pds", "AtprotoPersonalDataServer", "pds"); ep != nil {
		endpoints = append(endpoints, *ep)
	}

	// Extract Labeler
	if ep := s.extractServiceEndpoint(services, "atproto_labeler", "AtprotoLabeler", "labeler"); ep != nil {
		endpoints = append(endpoints, *ep)
	}

	return endpoints
}

func (s *Scanner) extractServiceEndpoint(services map[string]interface{}, serviceKey, expectedType, resultType string) *EndpointInfo {
	svc, ok := services[serviceKey].(map[string]interface{})
	if !ok {
		return nil
	}

	endpoint, hasEndpoint := svc["endpoint"].(string)
	svcType, hasType := svc["type"].(string)

	if hasEndpoint && hasType && svcType == expectedType {
		return &EndpointInfo{
			Type:     resultType,
			Endpoint: endpoint,
		}
	}

	return nil
}

func (s *Scanner) storeEndpoint(ctx context.Context, epType, endpoint string, discoveredAt time.Time) error {
	return s.db.UpsertEndpoint(ctx, &storage.Endpoint{
		EndpointType: epType,
		Endpoint:     endpoint,
		DiscoveredAt: discoveredAt,
		LastChecked:  time.Time{},
		Status:       storage.EndpointStatusUnknown,
	})
}

func (s *Scanner) updateCursorForBundle(ctx context.Context, bundle int, totalProcessed int64) error {
	return s.db.UpdateScanCursor(ctx, &storage.ScanCursor{
		Source:           "plc_directory",
		LastBundleNumber: bundle,
		LastScanTime:     time.Now().UTC(),
		RecordsProcessed: totalProcessed,
	})
}

// Helper functions
func (s *Scanner) mergeCounts(dest, src map[string]int64) {
	for k, v := range src {
		dest[k] += v
	}
}

func sumCounts(counts map[string]int64) int64 {
	total := int64(0)
	for _, v := range counts {
		total += v
	}
	return total
}

func isInsufficientOpsError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "insufficient operations")
}

// ScanMetrics tracks scan progress
type ScanMetrics struct {
	totalFetched   int64
	totalProcessed int64
	newEndpoints   int64
	endpointCounts map[string]int64
	currentBundle  int
	startTime      time.Time
}

func newMetrics(startBundle int) *ScanMetrics {
	return &ScanMetrics{
		endpointCounts: make(map[string]int64),
		currentBundle:  startBundle,
		startTime:      time.Now(),
	}
}

func (m *ScanMetrics) logSummary() {
	if m.newEndpoints > 0 {
		log.Info("PLC scan completed: %d operations processed, %d new endpoints in %v",
			m.totalProcessed, m.newEndpoints, time.Since(m.startTime))
	} else {
		log.Info("PLC scan completed: %d operations processed, 0 new endpoints in %v",
			m.totalProcessed, time.Since(m.startTime))
	}
}
