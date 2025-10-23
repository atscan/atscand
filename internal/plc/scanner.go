package plc

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
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
	bundleManager, err := NewBundleManager(cfg.BundleDir, cfg.UseCache, db, cfg.IndexDIDs) // NEW: pass IndexDIDs
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

// ScanMetrics tracks scan progress
type ScanMetrics struct {
	totalFetched   int64 // Total ops fetched from PLC/bundles
	totalProcessed int64 // Unique ops processed (after dedup)
	newEndpoints   int64 // New endpoints discovered
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
	summary := formatEndpointCounts(m.endpointCounts)
	if m.newEndpoints > 0 {
		log.Info("PLC scan completed: %d operations processed (%d fetched), %s in %v",
			m.totalProcessed, m.totalFetched, summary, time.Since(m.startTime))
	} else {
		log.Info("PLC scan completed: %d operations processed (%d fetched), 0 new endpoints in %v",
			m.totalProcessed, m.totalFetched, time.Since(m.startTime))
	}
}

func (s *Scanner) Scan(ctx context.Context) error {
	log.Info("Starting PLC directory scan...")
	log.Info("⚠ Note: PLC directory has rate limit of 500 requests per 5 minutes")

	cursor, err := s.db.GetScanCursor(ctx, "plc_directory")
	if err != nil {
		return fmt.Errorf("failed to get scan cursor: %w", err)
	}

	startBundle := s.calculateStartBundle(cursor.LastBundleNumber)
	metrics := newMetrics(startBundle)

	if startBundle > 1 {
		if err := s.ensureContinuity(ctx, startBundle); err != nil {
			return err
		}
	}

	// Handle existing mempool first
	if hasMempool, _ := s.hasSufficientMempool(ctx); hasMempool {
		return s.handleMempoolOnly(ctx, metrics)
	}

	// Process bundles until incomplete or error
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		if err := s.processSingleBundle(ctx, metrics); err != nil {
			if s.shouldRetry(err) {
				continue
			}
			break
		}

		if err := s.updateCursor(ctx, cursor, metrics); err != nil {
			log.Error("Warning: failed to update cursor: %v", err)
		}
	}

	// Try to finalize mempool
	s.finalizeMempool(ctx, metrics)

	metrics.logSummary()
	return nil
}

func (s *Scanner) calculateStartBundle(lastBundle int) int {
	if lastBundle == 0 {
		return 1
	}
	return lastBundle + 1
}

func (s *Scanner) ensureContinuity(ctx context.Context, bundle int) error {
	log.Info("Checking bundle continuity...")
	if err := s.bundleManager.EnsureBundleContinuity(ctx, bundle); err != nil {
		return fmt.Errorf("bundle continuity check failed: %w", err)
	}
	return nil
}

func (s *Scanner) hasSufficientMempool(ctx context.Context) (bool, error) {
	count, err := s.db.GetMempoolCount(ctx)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *Scanner) handleMempoolOnly(ctx context.Context, m *ScanMetrics) error {
	count, _ := s.db.GetMempoolCount(ctx)
	log.Info("→ Mempool has %d operations, continuing to fill it before fetching new bundles", count)

	if err := s.fillMempool(ctx, m); err != nil {
		return err
	}

	if err := s.processMempool(ctx, m); err != nil {
		log.Error("Error processing mempool: %v", err)
	}

	m.logSummary()
	return nil
}

func (s *Scanner) processSingleBundle(ctx context.Context, m *ScanMetrics) error {
	log.Verbose("→ Processing bundle %06d...", m.currentBundle)

	ops, isComplete, err := s.bundleManager.LoadBundle(ctx, m.currentBundle, s.client)
	if err != nil {
		return s.handleBundleError(err, m)
	}

	if isComplete {
		return s.handleCompleteBundle(ctx, ops, m)
	}
	return s.handleIncompleteBundle(ctx, ops, m)
}

func (s *Scanner) handleBundleError(err error, m *ScanMetrics) error {
	log.Error("Failed to load bundle %06d: %v", m.currentBundle, err)

	if strings.Contains(err.Error(), "rate limited") {
		log.Info("⚠ Rate limit hit, pausing for 5 minutes...")
		time.Sleep(5 * time.Minute)
		return fmt.Errorf("retry")
	}

	if m.currentBundle > 1 {
		log.Info("→ Reached end of available data")
	}
	return err
}

func (s *Scanner) shouldRetry(err error) bool {
	return err != nil && err.Error() == "retry"
}

func (s *Scanner) handleCompleteBundle(ctx context.Context, ops []PLCOperation, m *ScanMetrics) error {
	counts, err := s.processBatch(ctx, ops)
	if err != nil {
		return err
	}

	s.mergeCounts(m.endpointCounts, counts)
	m.totalProcessed += int64(len(ops)) // Unique ops after dedup
	m.newEndpoints += sumCounts(counts) // NEW: Track new endpoints

	batchTotal := sumCounts(counts)
	log.Verbose("✓ Processed bundle %06d: %d operations (after dedup), %d new endpoints",
		m.currentBundle, len(ops), batchTotal)

	m.currentBundle++
	return nil
}

func (s *Scanner) handleIncompleteBundle(ctx context.Context, ops []PLCOperation, m *ScanMetrics) error {
	log.Info("→ Bundle %06d incomplete (%d ops), adding to mempool", m.currentBundle, len(ops))

	if err := s.addToMempool(ctx, ops, m.endpointCounts); err != nil {
		return err
	}

	s.finalizeMempool(ctx, m)
	return fmt.Errorf("incomplete") // Signal end of processing
}

func (s *Scanner) finalizeMempool(ctx context.Context, m *ScanMetrics) {
	if err := s.fillMempool(ctx, m); err != nil {
		log.Error("Error filling mempool: %v", err)
	}
	if err := s.processMempool(ctx, m); err != nil {
		log.Error("Error processing mempool: %v", err)
	}
}

func (s *Scanner) fillMempool(ctx context.Context, m *ScanMetrics) error {
	const fetchLimit = 1000

	for {
		count, err := s.db.GetMempoolCount(ctx)
		if err != nil {
			return err
		}

		if count >= BUNDLE_SIZE {
			log.Info("✓ Mempool filled to %d operations (target: %d)", count, BUNDLE_SIZE)
			return nil
		}

		log.Info("→ Mempool has %d/%d operations, fetching more from PLC directory...", count, BUNDLE_SIZE)

		// ✅ Fix: Don't capture unused 'ops' variable
		shouldContinue, err := s.fetchNextBatch(ctx, fetchLimit, m)
		if err != nil {
			return err
		}

		if !shouldContinue {
			finalCount, _ := s.db.GetMempoolCount(ctx)
			log.Info("→ Stopping fill, mempool has %d/%d operations", finalCount, BUNDLE_SIZE)
			return nil
		}
	}
}

func (s *Scanner) fetchNextBatch(ctx context.Context, limit int, m *ScanMetrics) (bool, error) {
	lastOp, err := s.db.GetLastMempoolOperation(ctx)
	if err != nil {
		return false, err
	}

	var after string
	if lastOp != nil {
		after = lastOp.CreatedAt.Format(time.RFC3339Nano)
		log.Verbose("  Using cursor: %s", after)
	}

	ops, err := s.client.Export(ctx, ExportOptions{Count: limit, After: after})
	if err != nil {
		return false, fmt.Errorf("failed to fetch from PLC: %w", err)
	}

	fetchedCount := len(ops)
	m.totalFetched += int64(fetchedCount) // Track all fetched
	log.Verbose("  Fetched %d operations from PLC", fetchedCount)

	if fetchedCount == 0 {
		count, _ := s.db.GetMempoolCount(ctx)
		log.Info("→ No more data available from PLC directory (mempool has %d/%d)", count, BUNDLE_SIZE)
		return false, nil
	}

	beforeCount, err := s.db.GetMempoolCount(ctx)
	if err != nil {
		return false, err
	}

	endpointsBefore := sumCounts(m.endpointCounts)
	if err := s.addToMempool(ctx, ops, m.endpointCounts); err != nil {
		return false, err
	}
	endpointsAfter := sumCounts(m.endpointCounts)
	m.newEndpoints += (endpointsAfter - endpointsBefore) // Add new endpoints found

	afterCount, err := s.db.GetMempoolCount(ctx)
	if err != nil {
		return false, err
	}

	uniqueAdded := int64(afterCount - beforeCount) // Cast to int64
	m.totalProcessed += uniqueAdded                // Track unique ops processed

	log.Verbose("  Added %d new unique operations to mempool (%d were duplicates)",
		uniqueAdded, int64(fetchedCount)-uniqueAdded)

	// Continue only if got full batch
	shouldContinue := fetchedCount >= limit
	if !shouldContinue {
		log.Info("→ Received incomplete batch (%d/%d), caught up to latest data", fetchedCount, limit)
	}

	return shouldContinue, nil
}

func (s *Scanner) addToMempool(ctx context.Context, ops []PLCOperation, counts map[string]int64) error {
	mempoolOps := make([]storage.MempoolOperation, len(ops))
	for i, op := range ops {
		mempoolOps[i] = storage.MempoolOperation{
			DID:       op.DID,
			Operation: string(op.RawJSON),
			CID:       op.CID,
			CreatedAt: op.CreatedAt,
		}
	}

	if err := s.db.AddToMempool(ctx, mempoolOps); err != nil {
		return err
	}

	// Process for endpoint discovery
	batchCounts, err := s.processBatch(ctx, ops)
	s.mergeCounts(counts, batchCounts)
	return err
}

func (s *Scanner) processMempool(ctx context.Context, m *ScanMetrics) error {
	for {
		count, err := s.db.GetMempoolCount(ctx)
		if err != nil {
			return err
		}

		log.Verbose("Mempool contains %d operations", count)

		if count < BUNDLE_SIZE {
			log.Info("Mempool has %d/%d operations, cannot create bundle yet", count, BUNDLE_SIZE)
			return nil
		}

		log.Info("→ Creating bundle from mempool (%d operations available)...", count)

		// Updated to receive 4 values instead of 3
		bundleNum, ops, cursor, err := s.createBundleFromMempool(ctx)
		if err != nil {
			return err
		}

		// Process and update metrics
		countsBefore := sumCounts(m.endpointCounts)
		counts, _ := s.processBatch(ctx, ops)
		s.mergeCounts(m.endpointCounts, counts)
		newEndpointsFound := sumCounts(m.endpointCounts) - countsBefore

		m.totalProcessed += int64(len(ops))
		m.newEndpoints += newEndpointsFound
		m.currentBundle = bundleNum

		if err := s.updateCursorForBundle(ctx, bundleNum, m.totalProcessed); err != nil {
			log.Error("Warning: failed to update cursor: %v", err)
		}

		log.Info("✓ Created bundle %06d from mempool (cursor: %s)", bundleNum, cursor)
	}
}

func (s *Scanner) createBundleFromMempool(ctx context.Context) (int, []PLCOperation, string, error) {
	mempoolOps, err := s.db.GetMempoolOperations(ctx, BUNDLE_SIZE)
	if err != nil {
		return 0, nil, "", err
	}

	ops, ids := s.deduplicateMempool(mempoolOps)
	if len(ops) < BUNDLE_SIZE {
		return 0, nil, "", fmt.Errorf("only got %d unique operations from mempool, need %d", len(ops), BUNDLE_SIZE)
	}

	// Determine cursor from last bundle
	cursor := ""
	lastBundle, err := s.db.GetLastBundleNumber(ctx)
	if err == nil && lastBundle > 0 {
		if bundle, err := s.db.GetBundleByNumber(ctx, lastBundle); err == nil {
			cursor = bundle.EndTime.Format(time.RFC3339Nano)
		}
	}

	bundleNum, err := s.bundleManager.CreateBundleFromMempool(ctx, ops, cursor)
	if err != nil {
		return 0, nil, "", err
	}

	if err := s.db.DeleteFromMempool(ctx, ids[:len(ops)]); err != nil {
		return 0, nil, "", err
	}

	return bundleNum, ops, cursor, nil
}

func (s *Scanner) deduplicateMempool(mempoolOps []storage.MempoolOperation) ([]PLCOperation, []int64) {
	ops := make([]PLCOperation, 0, BUNDLE_SIZE)
	ids := make([]int64, 0, BUNDLE_SIZE)
	seenCIDs := make(map[string]bool)

	for _, mop := range mempoolOps {
		if seenCIDs[mop.CID] {
			ids = append(ids, mop.ID)
			continue
		}
		seenCIDs[mop.CID] = true

		var op PLCOperation
		json.Unmarshal([]byte(mop.Operation), &op)
		op.RawJSON = []byte(mop.Operation)

		ops = append(ops, op)
		ids = append(ids, mop.ID)

		if len(ops) >= BUNDLE_SIZE {
			break
		}
	}

	return ops, ids
}

func (s *Scanner) processBatch(ctx context.Context, ops []PLCOperation) (map[string]int64, error) {
	counts := make(map[string]int64)
	seen := make(map[string]*PLCOperation)

	// Collect unique endpoints
	for _, op := range ops {
		if op.IsNullified() {
			continue
		}
		for _, ep := range s.extractEndpointsFromOperation(op) {
			key := fmt.Sprintf("%s:%s", ep.Type, ep.Endpoint)
			if _, exists := seen[key]; !exists {
				seen[key] = &op
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
			log.Error("Error storing %s endpoint %s: %v", epType, stripansi.Strip(endpoint), err)
			continue
		}

		log.Info("✓ Discovered new %s endpoint: %s", epType, stripansi.Strip(endpoint))
		counts[epType]++
	}

	return counts, nil
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

func (s *Scanner) updateCursor(ctx context.Context, cursor *storage.ScanCursor, m *ScanMetrics) error {
	return s.db.UpdateScanCursor(ctx, &storage.ScanCursor{
		Source:           "plc_directory",
		LastBundleNumber: m.currentBundle - 1,
		LastScanTime:     time.Now().UTC(),
		RecordsProcessed: cursor.RecordsProcessed + m.totalProcessed,
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

func formatEndpointCounts(counts map[string]int64) string {
	if len(counts) == 0 {
		return "0 new endpoints"
	}

	total := sumCounts(counts)

	if len(counts) == 1 {
		for typ, count := range counts {
			return fmt.Sprintf("%d new %s endpoint(s)", count, typ)
		}
	}

	parts := make([]string, 0, len(counts))
	for typ, count := range counts {
		parts = append(parts, fmt.Sprintf("%d %s", count, typ))
	}
	return fmt.Sprintf("%d new endpoints (%s)", total, strings.Join(parts, ", "))
}
