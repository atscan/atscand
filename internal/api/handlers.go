package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/atscan/atscanner/internal/log"
	"github.com/atscan/atscanner/internal/plc"
	"github.com/atscan/atscanner/internal/storage"
	"github.com/gorilla/mux"
)

// ===== RESPONSE HELPERS =====

type response struct {
	w http.ResponseWriter
}

func newResponse(w http.ResponseWriter) *response {
	return &response{w: w}
}

func (r *response) json(data interface{}) {
	r.w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(r.w).Encode(data)
}

func (r *response) error(msg string, code int) {
	http.Error(r.w, msg, code)
}

func (r *response) bundleHeaders(bundle *storage.PLCBundle) {
	r.w.Header().Set("X-Bundle-Number", fmt.Sprintf("%d", bundle.BundleNumber))
	r.w.Header().Set("X-Bundle-Hash", bundle.Hash)
	r.w.Header().Set("X-Bundle-Compressed-Hash", bundle.CompressedHash)
	r.w.Header().Set("X-Bundle-Start-Time", bundle.StartTime.Format(time.RFC3339Nano))
	r.w.Header().Set("X-Bundle-End-Time", bundle.EndTime.Format(time.RFC3339Nano))
	r.w.Header().Set("X-Bundle-Operation-Count", fmt.Sprintf("%d", plc.BUNDLE_SIZE))
	r.w.Header().Set("X-Bundle-DID-Count", fmt.Sprintf("%d", len(bundle.DIDs)))
}

// ===== REQUEST HELPERS =====

func getBundleNumber(r *http.Request) (int, error) {
	vars := mux.Vars(r)
	return strconv.Atoi(vars["number"])
}

func getQueryInt(r *http.Request, key string, defaultVal int) int {
	if val := r.URL.Query().Get(key); val != "" {
		if parsed, err := strconv.Atoi(val); err == nil {
			return parsed
		}
	}
	return defaultVal
}

func getQueryInt64(r *http.Request, key string, defaultVal int64) int64 {
	if val := r.URL.Query().Get(key); val != "" {
		if parsed, err := strconv.ParseInt(val, 10, 64); err == nil {
			return parsed
		}
	}
	return defaultVal
}

// ===== FORMATTING HELPERS =====

func formatBundleResponse(bundle *storage.PLCBundle) map[string]interface{} {
	return map[string]interface{}{
		"plc_bundle_number": bundle.BundleNumber,
		"start_time":        bundle.StartTime,
		"end_time":          bundle.EndTime,
		"operation_count":   plc.BUNDLE_SIZE,
		"did_count":         len(bundle.DIDs),
		"hash":              bundle.Hash,
		"compressed_hash":   bundle.CompressedHash,
		"compressed_size":   bundle.CompressedSize,
		"uncompressed_size": bundle.UncompressedSize,
		"compression_ratio": float64(bundle.UncompressedSize) / float64(bundle.CompressedSize),
		"cursor":            bundle.Cursor,
		"prev_bundle_hash":  bundle.PrevBundleHash,
		"created_at":        bundle.CreatedAt,
	}
}

func formatEndpointResponse(ep *storage.Endpoint) map[string]interface{} {
	return map[string]interface{}{
		"id":            ep.ID,
		"endpoint_type": ep.EndpointType,
		"endpoint":      ep.Endpoint,
		"discovered_at": ep.DiscoveredAt,
		"last_checked":  ep.LastChecked,
		"status":        statusToString(ep.Status),
		"user_count":    ep.UserCount,
	}
}

func statusToString(status int) string {
	switch status {
	case storage.EndpointStatusOnline:
		return "online"
	case storage.EndpointStatusOffline:
		return "offline"
	default:
		return "unknown"
	}
}

// ===== ENDPOINT HANDLERS =====

func (s *Server) handleGetEndpoints(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)

	filter := &storage.EndpointFilter{
		Type:         r.URL.Query().Get("type"),
		Status:       r.URL.Query().Get("status"),
		MinUserCount: getQueryInt64(r, "min_user_count", 0),
		Limit:        getQueryInt(r, "limit", 0),
		Offset:       getQueryInt(r, "offset", 0),
	}

	endpoints, err := s.db.GetEndpoints(r.Context(), filter)
	if err != nil {
		resp.error(err.Error(), http.StatusInternalServerError)
		return
	}

	response := make([]map[string]interface{}, len(endpoints))
	for i, ep := range endpoints {
		response[i] = formatEndpointResponse(ep)
	}

	resp.json(response)
}

func (s *Server) handleGetEndpoint(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)
	vars := mux.Vars(r)
	endpoint := vars["endpoint"]
	endpointType := r.URL.Query().Get("type")
	if endpointType == "" {
		endpointType = "pds"
	}

	ep, err := s.db.GetEndpoint(r.Context(), endpoint, endpointType)
	if err != nil {
		resp.error("Endpoint not found", http.StatusNotFound)
		return
	}

	scans, _ := s.db.GetEndpointScans(r.Context(), ep.ID, 10)

	result := formatEndpointResponse(ep)
	result["recent_scans"] = scans

	resp.json(result)
}

func (s *Server) handleGetEndpointStats(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)
	stats, err := s.db.GetEndpointStats(r.Context())
	if err != nil {
		resp.error(err.Error(), http.StatusInternalServerError)
		return
	}
	resp.json(stats)
}

// ===== DID HANDLERS =====

func (s *Server) handleGetDID(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)
	vars := mux.Vars(r)
	did := vars["did"]

	bundles, err := s.db.GetBundlesForDID(r.Context(), did)
	if err != nil {
		resp.error(err.Error(), http.StatusInternalServerError)
		return
	}

	if len(bundles) == 0 {
		resp.error("DID not found in bundles", http.StatusNotFound)
		return
	}

	lastBundle := bundles[len(bundles)-1]
	ops, err := s.bundleManager.LoadBundleOperations(r.Context(), lastBundle.BundleNumber)
	if err != nil {
		resp.error(fmt.Sprintf("failed to load bundle: %v", err), http.StatusInternalServerError)
		return
	}

	// Find latest operation for this DID
	for i := len(ops) - 1; i >= 0; i-- {
		if ops[i].DID == did {
			resp.json(ops[i])
			return
		}
	}

	resp.error("DID operation not found", http.StatusNotFound)
}

func (s *Server) handleGetDIDHistory(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)
	vars := mux.Vars(r)
	did := vars["did"]

	bundles, err := s.db.GetBundlesForDID(r.Context(), did)
	if err != nil {
		resp.error(err.Error(), http.StatusInternalServerError)
		return
	}

	if len(bundles) == 0 {
		resp.error("DID not found in bundles", http.StatusNotFound)
		return
	}

	var allOperations []plc.DIDHistoryEntry
	var currentOp *plc.PLCOperation

	for _, bundle := range bundles {
		ops, err := s.bundleManager.LoadBundleOperations(r.Context(), bundle.BundleNumber)
		if err != nil {
			log.Error("Warning: failed to load bundle: %v", err)
			continue
		}

		for _, op := range ops {
			if op.DID == did {
				entry := plc.DIDHistoryEntry{
					Operation: op,
					PLCBundle: fmt.Sprintf("%06d", bundle.BundleNumber),
				}
				allOperations = append(allOperations, entry)
				currentOp = &op
			}
		}
	}

	resp.json(plc.DIDHistory{
		DID:        did,
		Current:    currentOp,
		Operations: allOperations,
	})
}

// ===== PLC BUNDLE HANDLERS =====

func (s *Server) handleGetPLCBundle(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)

	bundleNum, err := getBundleNumber(r)
	if err != nil {
		resp.error("invalid bundle number", http.StatusBadRequest)
		return
	}

	bundle, err := s.db.GetBundleByNumber(r.Context(), bundleNum)
	if err != nil {
		resp.error("bundle not found", http.StatusNotFound)
		return
	}

	resp.json(formatBundleResponse(bundle))
}

func (s *Server) handleGetPLCBundleDIDs(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)

	bundleNum, err := getBundleNumber(r)
	if err != nil {
		resp.error("invalid bundle number", http.StatusBadRequest)
		return
	}

	bundle, err := s.db.GetBundleByNumber(r.Context(), bundleNum)
	if err != nil {
		resp.error("bundle not found", http.StatusNotFound)
		return
	}

	resp.json(map[string]interface{}{
		"plc_bundle_number": bundle.BundleNumber,
		"did_count":         len(bundle.DIDs),
		"dids":              bundle.DIDs,
	})
}

func (s *Server) handleDownloadPLCBundle(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)

	bundleNum, err := getBundleNumber(r)
	if err != nil {
		resp.error("invalid bundle number", http.StatusBadRequest)
		return
	}

	compressed := r.URL.Query().Get("compressed") != "false"

	bundle, err := s.db.GetBundleByNumber(r.Context(), bundleNum)
	if err != nil {
		resp.error("bundle not found", http.StatusNotFound)
		return
	}

	resp.bundleHeaders(bundle)

	if compressed {
		s.serveCompressedBundle(w, r, bundle)
	} else {
		s.serveUncompressedBundle(w, r, bundle)
	}
}

func (s *Server) serveCompressedBundle(w http.ResponseWriter, r *http.Request, bundle *storage.PLCBundle) {
	resp := newResponse(w)
	path := bundle.GetFilePath(s.plcBundleDir)

	file, err := os.Open(path)
	if err != nil {
		resp.error("bundle file not found on disk", http.StatusNotFound)
		return
	}
	defer file.Close()

	fileInfo, _ := file.Stat()

	w.Header().Set("Content-Type", "application/zstd")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%06d.jsonl.zst", bundle.BundleNumber))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", fileInfo.Size()))
	w.Header().Set("X-Compressed-Size", fmt.Sprintf("%d", fileInfo.Size()))

	http.ServeContent(w, r, filepath.Base(path), bundle.CreatedAt, file)
}

func (s *Server) serveUncompressedBundle(w http.ResponseWriter, r *http.Request, bundle *storage.PLCBundle) {
	resp := newResponse(w)

	ops, err := s.bundleManager.LoadBundleOperations(r.Context(), bundle.BundleNumber)
	if err != nil {
		resp.error(fmt.Sprintf("error loading bundle: %v", err), http.StatusInternalServerError)
		return
	}

	// Serialize to JSONL
	var buf []byte
	for _, op := range ops {
		buf = append(buf, op.RawJSON...)
		buf = append(buf, '\n')
	}

	fileInfo, _ := os.Stat(bundle.GetFilePath(s.plcBundleDir))
	compressedSize := int64(0)
	if fileInfo != nil {
		compressedSize = fileInfo.Size()
	}

	w.Header().Set("Content-Type", "application/jsonl")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%06d.jsonl", bundle.BundleNumber))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(buf)))
	w.Header().Set("X-Compressed-Size", fmt.Sprintf("%d", compressedSize))
	w.Header().Set("X-Uncompressed-Size", fmt.Sprintf("%d", len(buf)))
	if compressedSize > 0 {
		w.Header().Set("X-Compression-Ratio", fmt.Sprintf("%.2f", float64(len(buf))/float64(compressedSize)))
	}

	w.WriteHeader(http.StatusOK)
	w.Write(buf)
}

func (s *Server) handleGetPLCBundles(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)
	limit := getQueryInt(r, "limit", 50)

	bundles, err := s.db.GetBundles(r.Context(), limit)
	if err != nil {
		resp.error(err.Error(), http.StatusInternalServerError)
		return
	}

	response := make([]map[string]interface{}, len(bundles))
	for i, bundle := range bundles {
		response[i] = formatBundleResponse(bundle)
	}

	resp.json(response)
}

func (s *Server) handleGetPLCBundleStats(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)

	count, compressedSize, uncompressedSize, lastBundle, err := s.db.GetBundleStats(r.Context())
	if err != nil {
		resp.error(err.Error(), http.StatusInternalServerError)
		return
	}

	resp.json(map[string]interface{}{
		"plc_bundle_count":           count,
		"last_bundle_number":         lastBundle,
		"total_compressed_size":      compressedSize,
		"total_compressed_size_mb":   float64(compressedSize) / 1024 / 1024,
		"total_compressed_size_gb":   float64(compressedSize) / 1024 / 1024 / 1024,
		"total_uncompressed_size":    uncompressedSize,
		"total_uncompressed_size_mb": float64(uncompressedSize) / 1024 / 1024,
		"total_uncompressed_size_gb": float64(uncompressedSize) / 1024 / 1024 / 1024,
		"compression_ratio":          float64(uncompressedSize) / float64(compressedSize),
	})
}

// ===== MEMPOOL HANDLERS =====

func (s *Server) handleGetMempoolStats(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)
	ctx := r.Context()

	count, err := s.db.GetMempoolCount(ctx)
	if err != nil {
		resp.error(err.Error(), http.StatusInternalServerError)
		return
	}

	uniqueDIDCount, err := s.db.GetMempoolUniqueDIDCount(ctx)
	if err != nil {
		resp.error(err.Error(), http.StatusInternalServerError)
		return
	}

	uncompressedSize, err := s.db.GetMempoolUncompressedSize(ctx)
	if err != nil {
		resp.error(err.Error(), http.StatusInternalServerError)
		return
	}

	result := map[string]interface{}{
		"operation_count":      count,
		"unique_did_count":     uniqueDIDCount,
		"uncompressed_size":    uncompressedSize,
		"uncompressed_size_mb": float64(uncompressedSize) / 1024 / 1024,
		"can_create_bundle":    count >= plc.BUNDLE_SIZE,
	}

	if count > 0 {
		if firstOp, err := s.db.GetFirstMempoolOperation(ctx); err == nil && firstOp != nil {
			result["mempool_start_time"] = firstOp.CreatedAt

			if count < plc.BUNDLE_SIZE {
				if lastOp, err := s.db.GetLastMempoolOperation(ctx); err == nil && lastOp != nil {
					timeSpan := lastOp.CreatedAt.Sub(firstOp.CreatedAt).Seconds()
					if timeSpan > 0 {
						opsPerSecond := float64(count) / timeSpan
						if opsPerSecond > 0 {
							remainingOps := plc.BUNDLE_SIZE - count
							secondsNeeded := float64(remainingOps) / opsPerSecond
							result["estimated_next_bundle_time"] = time.Now().Add(time.Duration(secondsNeeded) * time.Second)
							result["operations_needed"] = remainingOps
							result["current_rate_per_second"] = opsPerSecond
						}
					}
				}
			} else {
				result["estimated_next_bundle_time"] = time.Now()
				result["operations_needed"] = 0
			}
		}
	} else {
		result["mempool_start_time"] = nil
		result["estimated_next_bundle_time"] = nil
	}

	resp.json(result)
}

// ===== PLC METRICS HANDLERS =====

func (s *Server) handleGetPLCMetrics(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)
	limit := getQueryInt(r, "limit", 10)

	metrics, err := s.db.GetPLCMetrics(r.Context(), limit)
	if err != nil {
		resp.error(err.Error(), http.StatusInternalServerError)
		return
	}

	resp.json(metrics)
}

// ===== VERIFICATION HANDLERS =====

func (s *Server) handleVerifyPLCBundle(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)
	vars := mux.Vars(r)

	bundleNumber, err := strconv.Atoi(vars["bundleNumber"])
	if err != nil {
		resp.error("Invalid bundle number", http.StatusBadRequest)
		return
	}

	bundle, err := s.db.GetBundleByNumber(r.Context(), bundleNumber)
	if err != nil {
		resp.error("Bundle not found", http.StatusNotFound)
		return
	}

	// Fetch from PLC and verify
	remoteOps, prevCIDs, err := s.fetchRemoteBundleOps(r.Context(), bundleNumber)
	if err != nil {
		resp.error(fmt.Sprintf("Failed to fetch from PLC directory: %v", err), http.StatusInternalServerError)
		return
	}

	remoteHash := computeOperationsHash(remoteOps)
	verified := bundle.Hash == remoteHash

	resp.json(map[string]interface{}{
		"bundle_number":      bundleNumber,
		"verified":           verified,
		"local_hash":         bundle.Hash,
		"remote_hash":        remoteHash,
		"local_op_count":     plc.BUNDLE_SIZE,
		"remote_op_count":    len(remoteOps),
		"boundary_cids_used": len(prevCIDs),
	})
}

func (s *Server) fetchRemoteBundleOps(ctx context.Context, bundleNum int) ([]plc.PLCOperation, map[string]bool, error) {
	var after string
	var prevBoundaryCIDs map[string]bool

	if bundleNum > 1 {
		prevBundle, err := s.db.GetBundleByNumber(ctx, bundleNum-1)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get previous bundle: %w", err)
		}

		after = prevBundle.EndTime.Format("2006-01-02T15:04:05.000Z")

		if len(prevBundle.BoundaryCIDs) > 0 {
			prevBoundaryCIDs = make(map[string]bool)
			for _, cid := range prevBundle.BoundaryCIDs {
				prevBoundaryCIDs[cid] = true
			}
		}
	}

	var allRemoteOps []plc.PLCOperation
	seenCIDs := make(map[string]bool)

	for cid := range prevBoundaryCIDs {
		seenCIDs[cid] = true
	}

	currentAfter := after
	maxFetches := 20

	for fetchNum := 0; fetchNum < maxFetches && len(allRemoteOps) < plc.BUNDLE_SIZE; fetchNum++ {
		batch, err := s.plcClient.Export(ctx, plc.ExportOptions{
			Count: 1000,
			After: currentAfter,
		})
		if err != nil || len(batch) == 0 {
			break
		}

		for _, op := range batch {
			if !seenCIDs[op.CID] {
				seenCIDs[op.CID] = true
				allRemoteOps = append(allRemoteOps, op)
				if len(allRemoteOps) >= plc.BUNDLE_SIZE {
					break
				}
			}
		}

		if len(batch) > 0 {
			lastOp := batch[len(batch)-1]
			currentAfter = lastOp.CreatedAt.Format("2006-01-02T15:04:05.000Z")
		}

		if len(batch) < 1000 {
			break
		}
	}

	if len(allRemoteOps) > plc.BUNDLE_SIZE {
		allRemoteOps = allRemoteOps[:plc.BUNDLE_SIZE]
	}

	return allRemoteOps, prevBoundaryCIDs, nil
}

func (s *Server) handleVerifyChain(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)
	ctx := r.Context()

	lastBundle, err := s.db.GetLastBundleNumber(ctx)
	if err != nil {
		resp.error(err.Error(), http.StatusInternalServerError)
		return
	}

	if lastBundle == 0 {
		resp.json(map[string]interface{}{
			"status":  "empty",
			"message": "No bundles to verify",
		})
		return
	}

	valid := true
	var brokenAt int
	var errorMsg string

	for i := 1; i <= lastBundle; i++ {
		bundle, err := s.db.GetBundleByNumber(ctx, i)
		if err != nil {
			valid = false
			brokenAt = i
			errorMsg = fmt.Sprintf("Bundle %06d not found", i)
			break
		}

		if i > 1 {
			prevBundle, err := s.db.GetBundleByNumber(ctx, i-1)
			if err != nil {
				valid = false
				brokenAt = i
				errorMsg = fmt.Sprintf("Previous bundle %06d not found", i-1)
				break
			}

			if bundle.PrevBundleHash != prevBundle.Hash {
				valid = false
				brokenAt = i
				errorMsg = fmt.Sprintf("Chain broken: bundle %06d prev_hash doesn't match bundle %06d hash", i, i-1)
				break
			}
		}
	}

	result := map[string]interface{}{
		"chain_length": lastBundle,
		"valid":        valid,
	}

	if !valid {
		result["broken_at"] = brokenAt
		result["error"] = errorMsg
	}

	resp.json(result)
}

func (s *Server) handleGetChainInfo(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)
	ctx := r.Context()

	lastBundle, err := s.db.GetLastBundleNumber(ctx)
	if err != nil {
		resp.error(err.Error(), http.StatusInternalServerError)
		return
	}

	if lastBundle == 0 {
		resp.json(map[string]interface{}{
			"chain_length": 0,
			"status":       "empty",
		})
		return
	}

	firstBundle, _ := s.db.GetBundleByNumber(ctx, 1)
	lastBundleData, _ := s.db.GetBundleByNumber(ctx, lastBundle)

	// Updated to receive 5 values instead of 3
	count, compressedSize, uncompressedSize, _, err := s.db.GetBundleStats(ctx)
	if err != nil {
		resp.error(err.Error(), http.StatusInternalServerError)
		return
	}

	resp.json(map[string]interface{}{
		"chain_length":               lastBundle,
		"total_bundles":              count,
		"total_compressed_size":      compressedSize,
		"total_compressed_size_mb":   float64(compressedSize) / 1024 / 1024,
		"total_uncompressed_size":    uncompressedSize,
		"total_uncompressed_size_mb": float64(uncompressedSize) / 1024 / 1024,
		"compression_ratio":          float64(uncompressedSize) / float64(compressedSize),
		"chain_start_time":           firstBundle.StartTime,
		"chain_end_time":             lastBundleData.EndTime,
		"chain_head_hash":            lastBundleData.Hash,
		"first_prev_hash":            firstBundle.PrevBundleHash,
		"last_prev_hash":             lastBundleData.PrevBundleHash,
	})
}

// ===== PLC EXPORT HANDLER =====

func (s *Server) handlePLCExport(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)
	ctx := r.Context()

	count := getQueryInt(r, "count", 1000)
	if count > 10000 {
		count = 10000
	}

	afterTime, err := parseAfterParam(r.URL.Query().Get("after"))
	if err != nil {
		resp.error(fmt.Sprintf("Invalid after parameter: %v", err), http.StatusBadRequest)
		return
	}

	startBundle := s.findStartBundle(ctx, afterTime)
	ops := s.collectOperations(ctx, startBundle, afterTime, count)

	w.Header().Set("Content-Type", "application/jsonl")
	w.Header().Set("X-Operation-Count", strconv.Itoa(len(ops)))

	for _, op := range ops {
		if len(op.RawJSON) > 0 {
			w.Write(op.RawJSON)
		} else {
			jsonData, _ := json.Marshal(op)
			w.Write(jsonData)
		}
		w.Write([]byte("\n"))
	}
}

func parseAfterParam(afterStr string) (time.Time, error) {
	if afterStr == "" {
		return time.Time{}, nil
	}

	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05",
		"2006-01-02T15:04",
		"2006-01-02",
	}

	for _, format := range formats {
		if parsed, err := time.Parse(format, afterStr); err == nil {
			return parsed, nil
		}
	}

	return time.Time{}, fmt.Errorf("invalid timestamp format")
}

func (s *Server) findStartBundle(ctx context.Context, afterTime time.Time) int {
	if afterTime.IsZero() {
		return 1
	}

	foundBundle, err := s.db.GetBundleForTimestamp(ctx, afterTime)
	if err != nil {
		return 1
	}

	if foundBundle > 1 {
		return foundBundle - 1
	}
	return foundBundle
}

func (s *Server) collectOperations(ctx context.Context, startBundle int, afterTime time.Time, count int) []plc.PLCOperation {
	var allOps []plc.PLCOperation
	seenCIDs := make(map[string]bool)

	lastBundle, _ := s.db.GetLastBundleNumber(ctx)

	for bundleNum := startBundle; bundleNum <= lastBundle && len(allOps) < count; bundleNum++ {
		ops, err := s.bundleManager.LoadBundleOperations(ctx, bundleNum)
		if err != nil {
			log.Error("Warning: failed to load bundle %d: %v", bundleNum, err)
			continue
		}

		for _, op := range ops {
			if !afterTime.IsZero() && op.CreatedAt.Before(afterTime) {
				continue
			}

			if seenCIDs[op.CID] {
				continue
			}

			seenCIDs[op.CID] = true
			allOps = append(allOps, op)

			if len(allOps) >= count {
				break
			}
		}
	}

	return allOps
}

// ===== HEALTH HANDLER =====

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	newResponse(w).json(map[string]string{"status": "ok"})
}

// ===== UTILITY FUNCTIONS =====

func computeOperationsHash(ops []plc.PLCOperation) string {
	var jsonlData []byte
	for _, op := range ops {
		jsonlData = append(jsonlData, op.RawJSON...)
		jsonlData = append(jsonlData, '\n')
	}
	hash := sha256.Sum256(jsonlData)
	return hex.EncodeToString(hash[:])
}
