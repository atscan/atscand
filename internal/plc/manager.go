package plc

import (
	"context"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/atscan/atscand/internal/log"
	"github.com/atscan/atscand/internal/storage"
	plcbundle "github.com/atscan/plcbundle"
)

// BundleManager wraps the library's manager with database integration
type BundleManager struct {
	libManager *plcbundle.Manager
	db         storage.Database
	bundleDir  string
	indexDIDs  bool
}

func NewBundleManager(bundleDir string, plcURL string, db storage.Database, indexDIDs bool) (*BundleManager, error) {
	// Create library config
	config := plcbundle.DefaultConfig(bundleDir)

	// Create PLC client
	var client *plcbundle.PLCClient
	if plcURL != "" {
		client = plcbundle.NewPLCClient(plcURL)
	}

	// Create library manager
	libMgr, err := plcbundle.NewManager(config, client)
	if err != nil {
		return nil, fmt.Errorf("failed to create library manager: %w", err)
	}

	return &BundleManager{
		libManager: libMgr,
		db:         db,
		bundleDir:  bundleDir,
		indexDIDs:  indexDIDs,
	}, nil
}

func (bm *BundleManager) Close() {
	if bm.libManager != nil {
		bm.libManager.Close()
	}
}

// LoadBundle loads a bundle (from library) and returns operations
func (bm *BundleManager) LoadBundleOperations(ctx context.Context, bundleNum int) ([]PLCOperation, error) {
	bundle, err := bm.libManager.LoadBundle(ctx, bundleNum)
	if err != nil {
		return nil, err
	}
	return bundle.Operations, nil
}

// LoadBundle loads a full bundle with metadata
func (bm *BundleManager) LoadBundle(ctx context.Context, bundleNum int) (*plcbundle.Bundle, error) {
	return bm.libManager.LoadBundle(ctx, bundleNum)
}

// FetchAndSaveBundle fetches next bundle from PLC and saves
func (bm *BundleManager) FetchAndSaveBundle(ctx context.Context) (*plcbundle.Bundle, error) {
	// Fetch from PLC using library
	bundle, err := bm.libManager.FetchNextBundle(ctx)
	if err != nil {
		return nil, err
	}

	// Save to disk (library handles this)
	if err := bm.libManager.SaveBundle(ctx, bundle); err != nil {
		return nil, fmt.Errorf("failed to save bundle to disk: %w", err)
	}

	// Index DIDs if enabled (still use database for this)
	if bm.indexDIDs && len(bundle.Operations) > 0 {
		if err := bm.indexBundleDIDs(ctx, bundle); err != nil {
			log.Error("Failed to index DIDs for bundle %d: %v", bundle.BundleNumber, err)
		}
	}

	log.Info("✓ Saved bundle %06d", bundle.BundleNumber)

	return bundle, nil
}

// indexBundleDIDs indexes DIDs from a bundle into the database
func (bm *BundleManager) indexBundleDIDs(ctx context.Context, bundle *plcbundle.Bundle) error {
	start := time.Now()
	log.Verbose("Indexing DIDs for bundle %06d...", bundle.BundleNumber)

	// Extract DID info from operations
	didInfoMap := ExtractDIDInfoMap(bundle.Operations)

	successCount := 0
	errorCount := 0
	invalidHandleCount := 0

	// Upsert each DID
	for did, info := range didInfoMap {
		validHandle := ValidateHandle(info.Handle)
		if info.Handle != "" && validHandle == "" {
			invalidHandleCount++
		}

		if err := bm.db.UpsertDID(ctx, did, bundle.BundleNumber, validHandle, info.PDS); err != nil {
			log.Error("Failed to index DID %s: %v", did, err)
			errorCount++
		} else {
			successCount++
		}
	}

	elapsed := time.Since(start)
	log.Info("✓ Indexed %d DIDs for bundle %06d (%d errors, %d invalid handles) in %v",
		successCount, bundle.BundleNumber, errorCount, invalidHandleCount, elapsed)

	return nil
}

// VerifyChain verifies bundle chain integrity
func (bm *BundleManager) VerifyChain(ctx context.Context, endBundle int) error {
	result, err := bm.libManager.VerifyChain(ctx)
	if err != nil {
		return err
	}

	if !result.Valid {
		return fmt.Errorf("chain verification failed at bundle %d: %s", result.BrokenAt, result.Error)
	}

	return nil
}

// GetChainInfo returns chain information
func (bm *BundleManager) GetChainInfo(ctx context.Context) (map[string]interface{}, error) {
	return bm.libManager.GetInfo(), nil
}

// GetMempoolStats returns mempool statistics from the library
func (bm *BundleManager) GetMempoolStats() map[string]interface{} {
	return bm.libManager.GetMempoolStats()
}

// GetMempoolOperations returns all operations currently in mempool
func (bm *BundleManager) GetMempoolOperations() ([]PLCOperation, error) {
	return bm.libManager.GetMempoolOperations()
}

// GetIndex returns the library's bundle index
func (bm *BundleManager) GetIndex() *plcbundle.Index {
	return bm.libManager.GetIndex()
}

// GetLastBundleNumber returns the last bundle number
func (bm *BundleManager) GetLastBundleNumber() int {
	index := bm.libManager.GetIndex()
	lastBundle := index.GetLastBundle()
	if lastBundle == nil {
		return 0
	}
	return lastBundle.BundleNumber
}

// GetBundleMetadata gets bundle metadata by number
func (bm *BundleManager) GetBundleMetadata(bundleNum int) (*plcbundle.BundleMetadata, error) {
	index := bm.libManager.GetIndex()
	return index.GetBundle(bundleNum)
}

// GetBundles returns the most recent bundles (newest first)
func (bm *BundleManager) GetBundles(limit int) []*plcbundle.BundleMetadata {
	index := bm.libManager.GetIndex()
	allBundles := index.GetBundles()

	// Determine how many bundles to return
	count := limit
	if count <= 0 || count > len(allBundles) {
		count = len(allBundles)
	}

	// Build result in reverse order (newest first)
	result := make([]*plcbundle.BundleMetadata, count)
	for i := 0; i < count; i++ {
		result[i] = allBundles[len(allBundles)-1-i]
	}

	return result
}

// GetBundleStats returns bundle statistics
func (bm *BundleManager) GetBundleStats() map[string]interface{} {
	index := bm.libManager.GetIndex()
	stats := index.GetStats()

	// Convert to expected format
	lastBundle := stats["last_bundle"]
	if lastBundle == nil {
		lastBundle = int64(0)
	}

	// Calculate total uncompressed size by iterating through all bundles
	totalUncompressedSize := int64(0)
	allBundles := index.GetBundles()
	for _, bundle := range allBundles {
		totalUncompressedSize += bundle.UncompressedSize
	}

	return map[string]interface{}{
		"bundle_count":            int64(stats["bundle_count"].(int)),
		"total_size":              stats["total_size"].(int64),
		"total_uncompressed_size": totalUncompressedSize,
		"last_bundle":             int64(lastBundle.(int)),
	}
}

// GetDIDsForBundle gets DIDs from a bundle (loads and extracts)
func (bm *BundleManager) GetDIDsForBundle(ctx context.Context, bundleNum int) ([]string, int, error) {
	bundle, err := bm.libManager.LoadBundle(ctx, bundleNum)
	if err != nil {
		return nil, 0, err
	}

	// Extract unique DIDs
	didSet := make(map[string]bool)
	for _, op := range bundle.Operations {
		didSet[op.DID] = true
	}

	dids := make([]string, 0, len(didSet))
	for did := range didSet {
		dids = append(dids, did)
	}

	return dids, bundle.DIDCount, nil
}

// FindBundleForTimestamp finds bundle containing a timestamp
func (bm *BundleManager) FindBundleForTimestamp(afterTime time.Time) int {
	index := bm.libManager.GetIndex()
	bundles := index.GetBundles()

	// Find bundle containing this time
	for _, bundle := range bundles {
		if (bundle.StartTime.Before(afterTime) || bundle.StartTime.Equal(afterTime)) &&
			(bundle.EndTime.After(afterTime) || bundle.EndTime.Equal(afterTime)) {
			return bundle.BundleNumber
		}
	}

	// Return closest bundle before this time
	for i := len(bundles) - 1; i >= 0; i-- {
		if bundles[i].EndTime.Before(afterTime) {
			return bundles[i].BundleNumber
		}
	}

	return 1 // Default to first bundle
}

// StreamRaw streams raw compressed bundle data
func (bm *BundleManager) StreamRaw(ctx context.Context, bundleNumber int) (io.ReadCloser, error) {
	return bm.libManager.StreamBundleRaw(ctx, bundleNumber)
}

// StreamDecompressed streams decompressed bundle data
func (bm *BundleManager) StreamDecompressed(ctx context.Context, bundleNumber int) (io.ReadCloser, error) {
	return bm.libManager.StreamBundleDecompressed(ctx, bundleNumber)
}

// GetPLCHistory calculates historical statistics from the bundle index
func (bm *BundleManager) GetPLCHistory(ctx context.Context, limit int, fromBundle int) ([]*storage.PLCHistoryPoint, error) {
	index := bm.libManager.GetIndex()
	allBundles := index.GetBundles()

	// Filter bundles >= fromBundle
	var filtered []*plcbundle.BundleMetadata
	for _, b := range allBundles {
		if b.BundleNumber >= fromBundle {
			filtered = append(filtered, b)
		}
	}

	if len(filtered) == 0 {
		return []*storage.PLCHistoryPoint{}, nil
	}

	// Sort bundles by bundle number to ensure proper cumulative calculation
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].BundleNumber < filtered[j].BundleNumber
	})

	// Group by date
	type dailyStat struct {
		lastBundle        int
		bundleCount       int
		totalUncompressed int64
		totalCompressed   int64
	}

	dailyStats := make(map[string]*dailyStat)

	// Map to store the cumulative values at the end of each date
	dateCumulatives := make(map[string]struct {
		uncompressed int64
		compressed   int64
	})

	// Calculate cumulative totals as we iterate through sorted bundles
	cumulativeUncompressed := int64(0)
	cumulativeCompressed := int64(0)

	for _, bundle := range filtered {
		dateStr := bundle.StartTime.Format("2006-01-02")

		// Update cumulative totals
		cumulativeUncompressed += bundle.UncompressedSize
		cumulativeCompressed += bundle.CompressedSize

		if stat, exists := dailyStats[dateStr]; exists {
			// Update existing day
			if bundle.BundleNumber > stat.lastBundle {
				stat.lastBundle = bundle.BundleNumber
			}
			stat.bundleCount++
			stat.totalUncompressed += bundle.UncompressedSize
			stat.totalCompressed += bundle.CompressedSize
		} else {
			// Create new day entry
			dailyStats[dateStr] = &dailyStat{
				lastBundle:        bundle.BundleNumber,
				bundleCount:       1,
				totalUncompressed: bundle.UncompressedSize,
				totalCompressed:   bundle.CompressedSize,
			}
		}

		// Store the cumulative values at the end of this date
		// (will be overwritten if there are multiple bundles on the same day)
		dateCumulatives[dateStr] = struct {
			uncompressed int64
			compressed   int64
		}{
			uncompressed: cumulativeUncompressed,
			compressed:   cumulativeCompressed,
		}
	}

	// Convert map to sorted slice by date
	var dates []string
	for date := range dailyStats {
		dates = append(dates, date)
	}
	sort.Strings(dates)

	// Build history points with cumulative operations
	var history []*storage.PLCHistoryPoint
	cumulativeOps := 0

	for _, date := range dates {
		stat := dailyStats[date]
		cumulativeOps += stat.bundleCount * 10000
		cumulative := dateCumulatives[date]

		history = append(history, &storage.PLCHistoryPoint{
			Date:                   date,
			BundleNumber:           stat.lastBundle,
			OperationCount:         cumulativeOps,
			UncompressedSize:       stat.totalUncompressed,
			CompressedSize:         stat.totalCompressed,
			CumulativeUncompressed: cumulative.uncompressed,
			CumulativeCompressed:   cumulative.compressed,
		})
	}

	// Apply limit if specified
	if limit > 0 && len(history) > limit {
		history = history[:limit]
	}

	return history, nil
}
