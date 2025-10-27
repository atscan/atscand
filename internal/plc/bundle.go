package plc

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/atscan/atscanner/internal/log"
	"github.com/atscan/atscanner/internal/storage"
	"github.com/klauspost/compress/zstd"
)

const BUNDLE_SIZE = 10000

type BundleManager struct {
	dir       string
	enabled   bool
	encoder   *zstd.Encoder
	decoder   *zstd.Decoder
	db        storage.Database
	indexDIDs bool
}

// ===== INITIALIZATION =====

func NewBundleManager(dir string, enabled bool, db storage.Database, indexDIDs bool) (*BundleManager, error) {
	if !enabled {
		log.Verbose("BundleManager disabled (enabled=false)")
		return &BundleManager{enabled: false}, nil
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create bundle dir: %w", err)
	}

	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBetterCompression))
	if err != nil {
		return nil, err
	}

	decoder, err := zstd.NewReader(nil)
	if err != nil {
		return nil, err
	}

	log.Verbose("BundleManager initialized: enabled=%v, indexDIDs=%v, dir=%s", enabled, indexDIDs, dir)

	return &BundleManager{
		dir:       dir,
		enabled:   enabled,
		encoder:   encoder,
		decoder:   decoder,
		db:        db,
		indexDIDs: indexDIDs,
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

// ===== BUNDLE FILE ABSTRACTION =====

type bundleFile struct {
	path             string
	operations       []PLCOperation
	uncompressedHash string
	compressedHash   string
}

func (bm *BundleManager) newBundleFile(bundleNum int) *bundleFile {
	return &bundleFile{
		path: filepath.Join(bm.dir, fmt.Sprintf("%06d.jsonl.zst", bundleNum)),
	}
}

func (bf *bundleFile) exists() bool {
	_, err := os.Stat(bf.path)
	return err == nil
}

func (bm *BundleManager) load(bf *bundleFile) error {
	compressed, err := os.ReadFile(bf.path)
	if err != nil {
		return fmt.Errorf("read failed: %w", err)
	}

	decompressed, err := bm.decoder.DecodeAll(compressed, nil)
	if err != nil {
		return fmt.Errorf("decompress failed: %w", err)
	}

	bf.operations = bm.parseJSONL(decompressed)
	return nil
}

func (bm *BundleManager) save(bf *bundleFile) error {
	jsonlData := bm.serializeJSONL(bf.operations)
	bf.uncompressedHash = bm.hash(jsonlData)

	compressed := bm.encoder.EncodeAll(jsonlData, nil)
	bf.compressedHash = bm.hash(compressed)

	return os.WriteFile(bf.path, compressed, 0644)
}

func (bm *BundleManager) parseJSONL(data []byte) []PLCOperation {
	var ops []PLCOperation
	scanner := bufio.NewScanner(bytes.NewReader(data))

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var op PLCOperation
		if err := json.Unmarshal(line, &op); err == nil {
			op.RawJSON = append([]byte(nil), line...)
			ops = append(ops, op)
		}
	}

	return ops
}

func (bm *BundleManager) serializeJSONL(ops []PLCOperation) []byte {
	var buf []byte
	for _, op := range ops {
		buf = append(buf, op.RawJSON...)
		buf = append(buf, '\n')
	}
	return buf
}

// ===== BUNDLE FETCHING =====

type bundleFetcher struct {
	client       *Client
	seenCIDs     map[string]bool
	currentAfter string
	fetchCount   int
}

func newBundleFetcher(client *Client, afterTime string, prevBoundaryCIDs map[string]bool) *bundleFetcher {
	seen := make(map[string]bool)
	for cid := range prevBoundaryCIDs {
		seen[cid] = true
	}

	return &bundleFetcher{
		client:       client,
		seenCIDs:     seen,
		currentAfter: afterTime,
	}
}

func (bf *bundleFetcher) fetchUntilComplete(ctx context.Context, target int) ([]PLCOperation, bool) {
	var ops []PLCOperation
	maxFetches := (target / 900) + 5

	for len(ops) < target && bf.fetchCount < maxFetches {
		bf.fetchCount++
		batchSize := bf.calculateBatchSize(target - len(ops))

		log.Verbose("  Fetch #%d: need %d more, requesting %d", bf.fetchCount, target-len(ops), batchSize)

		batch, shouldContinue := bf.fetchBatch(ctx, batchSize)

		for _, op := range batch {
			if !bf.seenCIDs[op.CID] {
				bf.seenCIDs[op.CID] = true
				ops = append(ops, op)

				if len(ops) >= target {
					return ops[:target], true
				}
			}
		}

		if !shouldContinue {
			break
		}
	}

	return ops, len(ops) >= target
}

func (bf *bundleFetcher) calculateBatchSize(remaining int) int {
	if bf.fetchCount == 0 {
		return 1000
	}
	if remaining < 100 {
		return 50
	}
	if remaining < 500 {
		return 200
	}
	return 1000
}

func (bf *bundleFetcher) fetchBatch(ctx context.Context, size int) ([]PLCOperation, bool) {
	ops, err := bf.client.Export(ctx, ExportOptions{
		Count: size,
		After: bf.currentAfter,
	})

	if err != nil || len(ops) == 0 {
		return nil, false
	}

	if len(ops) > 0 {
		bf.currentAfter = ops[len(ops)-1].CreatedAt.Format(time.RFC3339Nano)
	}

	return ops, len(ops) >= size
}

// ===== MAIN BUNDLE LOADING =====

func (bm *BundleManager) LoadBundle(ctx context.Context, bundleNum int, plcClient *Client) ([]PLCOperation, bool, error) {
	if !bm.enabled {
		return nil, false, fmt.Errorf("bundle manager disabled")
	}

	bf := bm.newBundleFile(bundleNum)

	// Try local file first
	if bf.exists() {
		return bm.loadFromFile(ctx, bundleNum, bf)
	}

	// Fetch from PLC
	return bm.fetchFromPLC(ctx, bundleNum, bf, plcClient)
}

func (bm *BundleManager) loadFromFile(ctx context.Context, bundleNum int, bf *bundleFile) ([]PLCOperation, bool, error) {
	log.Verbose("→ Loading bundle %06d from local file", bundleNum)

	// Verify hash if bundle is in DB
	if dbBundle, err := bm.db.GetBundleByNumber(ctx, bundleNum); err == nil && dbBundle != nil {
		if err := bm.verifyHash(bf.path, dbBundle.CompressedHash); err != nil {
			log.Error("⚠ Hash mismatch for bundle %06d! Re-fetching...", bundleNum)
			os.Remove(bf.path)
			return nil, false, fmt.Errorf("hash mismatch")
		}
		log.Verbose("✓ Hash verified for bundle %06d", bundleNum)
	}

	if err := bm.load(bf); err != nil {
		return nil, false, err
	}

	// Index if not in DB
	if _, err := bm.db.GetBundleByNumber(ctx, bundleNum); err != nil {
		bf.compressedHash = bm.hashFile(bf.path)
		bf.uncompressedHash = bm.hash(bm.serializeJSONL(bf.operations))

		// Calculate cursor from previous bundle
		cursor := bm.calculateCursor(ctx, bundleNum)

		bm.indexBundle(ctx, bundleNum, bf, cursor)
	}

	return bf.operations, true, nil
}

func (bm *BundleManager) fetchFromPLC(ctx context.Context, bundleNum int, bf *bundleFile, client *Client) ([]PLCOperation, bool, error) {
	log.Info("→ Bundle %06d not found locally, fetching from PLC directory...", bundleNum)

	afterTime, prevCIDs := bm.getBoundaryInfo(ctx, bundleNum)
	fetcher := newBundleFetcher(client, afterTime, prevCIDs)

	ops, isComplete := fetcher.fetchUntilComplete(ctx, BUNDLE_SIZE)

	log.Info("  Collected %d unique operations after %d fetches (complete=%v)",
		len(ops), fetcher.fetchCount, isComplete)

	if isComplete {
		bf.operations = ops
		if err := bm.save(bf); err != nil {
			log.Error("Warning: failed to save bundle: %v", err)
		} else {
			// The cursor is the afterTime that was used to fetch this bundle
			cursor := afterTime
			bm.indexBundle(ctx, bundleNum, bf, cursor)
			log.Info("✓ Bundle %06d saved [%d ops, hash: %s..., cursor: %s]",
				bundleNum, len(ops), bf.uncompressedHash[:16], cursor)
		}
	}

	return ops, isComplete, nil
}

func (bm *BundleManager) getBoundaryInfo(ctx context.Context, bundleNum int) (string, map[string]bool) {
	if bundleNum == 1 {
		return "", nil
	}

	prevBundle, err := bm.db.GetBundleByNumber(ctx, bundleNum-1)
	if err != nil {
		return "", nil
	}

	afterTime := prevBundle.EndTime.Format(time.RFC3339Nano)

	// Return stored boundary CIDs if available
	if len(prevBundle.BoundaryCIDs) > 0 {
		cids := make(map[string]bool)
		for _, cid := range prevBundle.BoundaryCIDs {
			cids[cid] = true
		}
		return afterTime, cids
	}

	// Fallback: compute from file
	bf := bm.newBundleFile(bundleNum - 1)
	if bf.exists() {
		if err := bm.load(bf); err == nil {
			_, cids := GetBoundaryCIDs(bf.operations)
			return afterTime, cids
		}
	}

	return afterTime, nil
}

// ===== BUNDLE INDEXING =====

func (bm *BundleManager) indexBundle(ctx context.Context, bundleNum int, bf *bundleFile, cursor string) error {
	log.Verbose("indexBundle called for bundle %06d: indexDIDs=%v", bundleNum, bm.indexDIDs)

	prevHash := ""
	if bundleNum > 1 {
		if prev, err := bm.db.GetBundleByNumber(ctx, bundleNum-1); err == nil {
			prevHash = prev.Hash
		}
	}

	dids := bm.extractUniqueDIDs(bf.operations)
	log.Verbose("Extracted %d unique DIDs from bundle %06d", len(dids), bundleNum)

	compressedFileSize := bm.getFileSize(bf.path)

	// Calculate uncompressed size
	uncompressedSize := int64(0)
	for _, op := range bf.operations {
		uncompressedSize += int64(len(op.RawJSON)) + 1
	}

	// Get time range from operations
	firstSeenAt := bf.operations[0].CreatedAt
	lastSeenAt := bf.operations[len(bf.operations)-1].CreatedAt

	bundle := &storage.PLCBundle{
		BundleNumber:     bundleNum,
		StartTime:        firstSeenAt,
		EndTime:          lastSeenAt,
		DIDCount:         len(dids),
		Hash:             bf.uncompressedHash,
		CompressedHash:   bf.compressedHash,
		CompressedSize:   compressedFileSize,
		UncompressedSize: uncompressedSize,
		Cursor:           cursor,
		PrevBundleHash:   prevHash,
		Compressed:       true,
		CreatedAt:        time.Now().UTC(),
	}

	log.Verbose("About to create bundle %06d in database (DIDCount=%d)", bundleNum, bundle.DIDCount)

	// Create bundle first
	if err := bm.db.CreateBundle(ctx, bundle); err != nil {
		log.Error("Failed to create bundle %06d in database: %v", bundleNum, err)
		return err
	}

	log.Verbose("Bundle %06d created successfully in database", bundleNum)

	// Index DIDs if enabled
	if bm.indexDIDs {
		start := time.Now()
		log.Verbose("Starting DID indexing for bundle %06d: %d unique DIDs", bundleNum, len(dids))

		// Extract handle and PDS for each DID
		didInfoMap := ExtractDIDInfoMap(bf.operations)
		log.Verbose("Extracted info for %d DIDs from operations", len(didInfoMap))

		successCount := 0
		errorCount := 0
		invalidHandleCount := 0

		// Upsert each DID with handle, pds, and bundle number
		for did, info := range didInfoMap {
			validHandle := ValidateHandle(info.Handle)
			if info.Handle != "" && validHandle == "" {
				//log.Verbose("Bundle %06d: Skipping invalid handle for DID %s (length: %d)", bundleNum, did, len(info.Handle))
				invalidHandleCount++
			}

			if err := bm.db.UpsertDID(ctx, did, bundleNum, validHandle, info.PDS); err != nil {
				log.Error("Failed to index DID %s for bundle %06d: %v", did, bundleNum, err)
				errorCount++
			} else {
				successCount++
			}
		}

		elapsed := time.Since(start)
		log.Info("✓ Indexed bundle %06d: %d DIDs succeeded, %d errors, %d invalid handles in %v",
			bundleNum, successCount, errorCount, invalidHandleCount, elapsed)
	} else {
		log.Verbose("⊘ Skipped DID indexing for bundle %06d (disabled in config)", bundleNum)
	}

	return nil
}

func (bm *BundleManager) extractUniqueDIDs(ops []PLCOperation) []string {
	didSet := make(map[string]bool)
	for _, op := range ops {
		didSet[op.DID] = true
	}

	dids := make([]string, 0, len(didSet))
	for did := range didSet {
		dids = append(dids, did)
	}
	return dids
}

// ===== MEMPOOL BUNDLE CREATION =====

func (bm *BundleManager) CreateBundleFromMempool(ctx context.Context, operations []PLCOperation, cursor string) (int, error) {
	if !bm.enabled {
		return 0, fmt.Errorf("bundle manager disabled")
	}

	if len(operations) != BUNDLE_SIZE {
		return 0, fmt.Errorf("bundle must have exactly %d operations, got %d", BUNDLE_SIZE, len(operations))
	}

	lastBundle, err := bm.db.GetLastBundleNumber(ctx)
	if err != nil {
		return 0, err
	}
	bundleNum := lastBundle + 1

	bf := bm.newBundleFile(bundleNum)
	bf.operations = operations

	if err := bm.save(bf); err != nil {
		return 0, err
	}

	if err := bm.indexBundle(ctx, bundleNum, bf, cursor); err != nil {
		return 0, err
	}

	log.Info("✓ Created bundle %06d from mempool (hash: %s...)",
		bundleNum, bf.uncompressedHash[:16])

	return bundleNum, nil
}

// ===== VERIFICATION =====

func (bm *BundleManager) VerifyChain(ctx context.Context, endBundle int) error {
	if !bm.enabled {
		return fmt.Errorf("bundle manager disabled")
	}

	log.Info("Verifying bundle chain from 1 to %06d...", endBundle)

	for i := 1; i <= endBundle; i++ {
		bundle, err := bm.db.GetBundleByNumber(ctx, i)
		if err != nil {
			return fmt.Errorf("bundle %06d not found: %w", i, err)
		}

		// Verify file hash
		path := bm.newBundleFile(i).path
		if err := bm.verifyHash(path, bundle.CompressedHash); err != nil {
			return fmt.Errorf("bundle %06d hash verification failed: %w", i, err)
		}

		// Verify chain link
		if i > 1 {
			prevBundle, err := bm.db.GetBundleByNumber(ctx, i-1)
			if err != nil {
				return fmt.Errorf("bundle %06d missing (required by %06d)", i-1, i)
			}

			if bundle.PrevBundleHash != prevBundle.Hash {
				return fmt.Errorf("bundle %06d chain broken! Expected prev_hash=%s, got=%s",
					i, prevBundle.Hash[:16], bundle.PrevBundleHash[:16])
			}
		}

		if i%100 == 0 {
			log.Verbose("  ✓ Verified bundles 1-%06d", i)
		}
	}

	log.Info("✓ Chain verification complete: bundles 1-%06d are valid and continuous", endBundle)
	return nil
}

func (bm *BundleManager) EnsureBundleContinuity(ctx context.Context, targetBundle int) error {
	if !bm.enabled {
		return nil
	}

	for i := 1; i < targetBundle; i++ {
		if !bm.newBundleFile(i).exists() {
			if _, err := bm.db.GetBundleByNumber(ctx, i); err != nil {
				return fmt.Errorf("bundle %06d is missing (required for continuity)", i)
			}
		}
	}

	return nil
}

// ===== UTILITY METHODS =====

func (bm *BundleManager) hash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func (bm *BundleManager) hashFile(path string) string {
	data, _ := os.ReadFile(path)
	return bm.hash(data)
}

func (bm *BundleManager) verifyHash(path, expectedHash string) error {
	if expectedHash == "" {
		return nil
	}

	actualHash := bm.hashFile(path)
	if actualHash != expectedHash {
		return fmt.Errorf("hash mismatch")
	}
	return nil
}

func (bm *BundleManager) getFileSize(path string) int64 {
	if info, err := os.Stat(path); err == nil {
		return info.Size()
	}
	return 0
}

func (bm *BundleManager) GetStats(ctx context.Context) (int64, int64, int64, int64, error) {
	if !bm.enabled {
		return 0, 0, 0, 0, nil
	}
	return bm.db.GetBundleStats(ctx)
}

func (bm *BundleManager) GetChainInfo(ctx context.Context) (map[string]interface{}, error) {
	lastBundle, err := bm.db.GetLastBundleNumber(ctx)
	if err != nil {
		return nil, err
	}

	if lastBundle == 0 {
		return map[string]interface{}{
			"chain_length": 0,
			"status":       "empty",
		}, nil
	}

	firstBundle, _ := bm.db.GetBundleByNumber(ctx, 1)
	lastBundleData, _ := bm.db.GetBundleByNumber(ctx, lastBundle)

	return map[string]interface{}{
		"chain_length":     lastBundle,
		"first_bundle":     1,
		"last_bundle":      lastBundle,
		"chain_start_time": firstBundle.StartTime,
		"chain_end_time":   lastBundleData.EndTime,
		"chain_head_hash":  lastBundleData.Hash,
	}, nil
}

// ===== EXPORTED HELPERS =====

func GetBoundaryCIDs(operations []PLCOperation) (time.Time, map[string]bool) {
	if len(operations) == 0 {
		return time.Time{}, nil
	}

	lastOp := operations[len(operations)-1]
	boundaryTime := lastOp.CreatedAt
	cidSet := make(map[string]bool)

	for i := len(operations) - 1; i >= 0; i-- {
		op := operations[i]
		if op.CreatedAt.Equal(boundaryTime) {
			cidSet[op.CID] = true
		} else {
			break
		}
	}

	return boundaryTime, cidSet
}

func StripBoundaryDuplicates(operations []PLCOperation, boundaryTimestamp string, prevBoundaryCIDs map[string]bool) []PLCOperation {
	if len(operations) == 0 {
		return operations
	}

	boundaryTime, err := time.Parse(time.RFC3339Nano, boundaryTimestamp)
	if err != nil {
		return operations
	}

	startIdx := 0
	for startIdx < len(operations) {
		op := operations[startIdx]

		if op.CreatedAt.After(boundaryTime) {
			break
		}

		if op.CreatedAt.Equal(boundaryTime) && prevBoundaryCIDs[op.CID] {
			startIdx++
			continue
		}

		break
	}

	return operations[startIdx:]
}

// LoadBundleOperations is a public method for external access (e.g., API handlers)
func (bm *BundleManager) LoadBundleOperations(ctx context.Context, bundleNum int) ([]PLCOperation, error) {
	if !bm.enabled {
		return nil, fmt.Errorf("bundle manager disabled")
	}

	bf := bm.newBundleFile(bundleNum)

	if !bf.exists() {
		return nil, fmt.Errorf("bundle %06d not found", bundleNum)
	}

	if err := bm.load(bf); err != nil {
		return nil, err
	}

	return bf.operations, nil
}

// calculateCursor determines the cursor value for a given bundle
// For bundle 1: returns empty string
// For bundle N: returns the end_time of bundle N-1 in RFC3339Nano format
func (bm *BundleManager) calculateCursor(ctx context.Context, bundleNum int) string {
	if bundleNum == 1 {
		return ""
	}

	// Try to get cursor from previous bundle in DB
	if prevBundle, err := bm.db.GetBundleByNumber(ctx, bundleNum-1); err == nil {
		return prevBundle.EndTime.Format(time.RFC3339Nano)
	}

	// If previous bundle not in DB, try to load it from file
	prevBf := bm.newBundleFile(bundleNum - 1)
	if prevBf.exists() {
		if err := bm.load(prevBf); err == nil && len(prevBf.operations) > 0 {
			// Return the createdAt of the last operation in previous bundle
			lastOp := prevBf.operations[len(prevBf.operations)-1]
			return lastOp.CreatedAt.Format(time.RFC3339Nano)
		}
	}

	return ""
}
