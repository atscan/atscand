package api

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/atscan/atscanner/internal/log"
	"github.com/atscan/atscanner/internal/monitor"
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
	response := map[string]interface{}{
		"id":            ep.ID,
		"endpoint_type": ep.EndpointType,
		"endpoint":      ep.Endpoint,
		"discovered_at": ep.DiscoveredAt,
		"last_checked":  ep.LastChecked,
		"status":        statusToString(ep.Status),
		// REMOVED: "user_count": ep.UserCount,  // No longer exists
	}

	// Add IP if available
	if ep.IP != "" {
		response["ip"] = ep.IP
	}

	// REMOVED: IP info extraction - no longer in Endpoint struct
	// IPInfo is now in separate table, joined only in PDS handlers

	return response
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
		Limit:        getQueryInt(r, "limit", 50),
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

func (s *Server) handleGetEndpointStats(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)
	stats, err := s.db.GetEndpointStats(r.Context())
	if err != nil {
		resp.error(err.Error(), http.StatusInternalServerError)
		return
	}
	resp.json(stats)
}

// ===== PDS HANDLERS =====

func (s *Server) handleGetPDSList(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)

	filter := &storage.EndpointFilter{
		Type:         "pds",
		Status:       r.URL.Query().Get("status"),
		MinUserCount: getQueryInt64(r, "min_user_count", 0),
		Limit:        getQueryInt(r, "limit", 50),
		Offset:       getQueryInt(r, "offset", 0),
	}

	pdsServers, err := s.db.GetPDSList(r.Context(), filter)
	if err != nil {
		resp.error(err.Error(), http.StatusInternalServerError)
		return
	}

	response := make([]map[string]interface{}, len(pdsServers))
	for i, pds := range pdsServers {
		response[i] = formatPDSListItem(pds)
	}

	resp.json(response)
}

func (s *Server) handleGetPDSDetail(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)
	vars := mux.Vars(r)
	endpoint := "https://" + normalizeEndpoint(vars["endpoint"])

	// FIX: Use r.Context() instead of ctx
	pds, err := s.db.GetPDSDetail(r.Context(), endpoint)
	if err != nil {
		resp.error("PDS not found", http.StatusNotFound)
		return
	}

	// Get recent scans
	scans, _ := s.db.GetEndpointScans(r.Context(), pds.ID, 10)

	result := formatPDSDetail(pds)
	result["recent_scans"] = formatScans(scans)

	resp.json(result)
}

func (s *Server) handleGetPDSStats(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)
	ctx := r.Context()

	// Get PDS-specific stats
	stats, err := s.db.GetPDSStats(ctx)
	if err != nil {
		resp.error(err.Error(), http.StatusInternalServerError)
		return
	}

	resp.json(stats)
}

func formatPDSListItem(pds *storage.PDSListItem) map[string]interface{} {
	response := map[string]interface{}{
		"id":            pds.ID,
		"endpoint":      pds.Endpoint,
		"discovered_at": pds.DiscoveredAt,
		"status":        statusToString(pds.Status),
	}

	// Add server_did if available
	if pds.ServerDID != "" {
		response["server_did"] = pds.ServerDID
	}

	// Add last_checked if available
	if !pds.LastChecked.IsZero() {
		response["last_checked"] = pds.LastChecked
	}

	// Add data from latest scan (if available)
	if pds.LatestScan != nil {
		response["user_count"] = pds.LatestScan.UserCount
		response["response_time"] = pds.LatestScan.ResponseTime
		if pds.LatestScan.Version != "" {
			response["version"] = pds.LatestScan.Version
		}
		if !pds.LatestScan.ScannedAt.IsZero() {
			response["last_scan"] = pds.LatestScan.ScannedAt
		}
	}

	// Add IP if available
	if pds.IP != "" {
		response["ip"] = pds.IP
	}

	// Add IP info (from ip_infos table via JOIN)
	if pds.IPInfo != nil {
		if pds.IPInfo.City != "" {
			response["city"] = pds.IPInfo.City
		}
		if pds.IPInfo.Country != "" {
			response["country"] = pds.IPInfo.Country
		}
		if pds.IPInfo.CountryCode != "" {
			response["country_code"] = pds.IPInfo.CountryCode
		}
		if pds.IPInfo.ASN > 0 {
			response["asn"] = pds.IPInfo.ASN
		}
	}

	return response
}

func formatPDSDetail(pds *storage.PDSDetail) map[string]interface{} {
	// Start with list item formatting (includes server_did)
	response := formatPDSListItem(&pds.PDSListItem)

	// Add is_primary flag
	response["is_primary"] = pds.IsPrimary

	// Add aliases if available
	if len(pds.Aliases) > 0 {
		response["aliases"] = pds.Aliases
		response["alias_count"] = len(pds.Aliases)
	}

	// Add server_info and version from latest scan (PDSDetail's LatestScan takes precedence)
	if pds.LatestScan != nil {
		// Override with detail-specific scan data
		response["user_count"] = pds.LatestScan.UserCount
		response["response_time"] = pds.LatestScan.ResponseTime

		if pds.LatestScan.Version != "" {
			response["version"] = pds.LatestScan.Version
		}

		if !pds.LatestScan.ScannedAt.IsZero() {
			response["last_scan"] = pds.LatestScan.ScannedAt
		}

		if pds.LatestScan.ServerInfo != nil {
			response["server_info"] = pds.LatestScan.ServerInfo
		}
	}

	// Add full IP info
	if pds.IPInfo != nil {
		response["ip_info"] = pds.IPInfo
	}

	return response
}

func formatScans(scans []*storage.EndpointScan) []map[string]interface{} {
	result := make([]map[string]interface{}, len(scans))
	for i, scan := range scans {
		scanMap := map[string]interface{}{
			"id":         scan.ID,
			"status":     statusToString(scan.Status),
			"scanned_at": scan.ScannedAt,
		}

		if scan.ResponseTime > 0 {
			scanMap["response_time"] = scan.ResponseTime
		}

		// NEW: Add version if available
		if scan.Version != "" {
			scanMap["version"] = scan.Version
		}

		// Use the top-level UserCount field first
		if scan.UserCount > 0 {
			scanMap["user_count"] = scan.UserCount
		} else if scan.ScanData != nil && scan.ScanData.Metadata != nil {
			// Fallback to metadata for older scans
			if userCount, ok := scan.ScanData.Metadata["user_count"].(int); ok {
				scanMap["user_count"] = userCount
			} else if userCount, ok := scan.ScanData.Metadata["user_count"].(float64); ok {
				scanMap["user_count"] = int(userCount)
			}
		}

		if scan.ScanData != nil {
			// Include DID count if available
			if scan.ScanData.DIDCount > 0 {
				scanMap["did_count"] = scan.ScanData.DIDCount
			}
		}

		result[i] = scanMap
	}
	return result
}

// ===== DID HANDLERS =====

func (s *Server) handleGetDID(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)
	vars := mux.Vars(r)
	did := vars["did"]

	// Fast lookup using dids table
	didRecord, err := s.db.GetDIDRecord(r.Context(), did)
	if err != nil {
		if err == sql.ErrNoRows {
			// NEW: Provide helpful message if indexing is disabled
			resp.error("DID not found. Note: DID indexing may be disabled in configuration.", http.StatusNotFound)
		} else {
			resp.error(err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// Get the last bundle number where this DID appeared
	if len(didRecord.BundleNumbers) == 0 {
		resp.error("DID has no bundle history", http.StatusInternalServerError)
		return
	}

	lastBundleNum := didRecord.BundleNumbers[len(didRecord.BundleNumbers)-1]

	// Load last bundle to get latest operation
	ops, err := s.bundleManager.LoadBundleOperations(r.Context(), lastBundleNum)
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

	// Fast lookup using dids table
	didRecord, err := s.db.GetDIDRecord(r.Context(), did)
	if err != nil {
		if err == sql.ErrNoRows {
			resp.error("DID not found", http.StatusNotFound)
		} else {
			resp.error(err.Error(), http.StatusInternalServerError)
		}
		return
	}

	var allOperations []plc.DIDHistoryEntry
	var currentOp *plc.PLCOperation

	// Load operations from each bundle
	for _, bundleNum := range didRecord.BundleNumbers {
		ops, err := s.bundleManager.LoadBundleOperations(r.Context(), bundleNum)
		if err != nil {
			log.Error("Warning: failed to load bundle %d: %v", bundleNum, err)
			continue
		}

		for _, op := range ops {
			if op.DID == did {
				entry := plc.DIDHistoryEntry{
					Operation: op,
					PLCBundle: fmt.Sprintf("%06d", bundleNum),
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

func (s *Server) handleGetDIDStats(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)
	ctx := r.Context()

	totalDIDs, err := s.db.GetTotalDIDCount(ctx)
	if err != nil {
		resp.error(err.Error(), http.StatusInternalServerError)
		return
	}

	lastBundle, err := s.db.GetLastBundleNumber(ctx)
	if err != nil {
		resp.error(err.Error(), http.StatusInternalServerError)
		return
	}

	resp.json(map[string]interface{}{
		"total_unique_dids": totalDIDs,
		"last_bundle":       lastBundle,
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

	// Try to get existing bundle
	bundle, err := s.db.GetBundleByNumber(r.Context(), bundleNum)
	if err == nil {
		// Bundle exists, return it normally
		resp.json(formatBundleResponse(bundle))
		return
	}

	// Bundle not found - check if it's the next upcoming bundle
	lastBundle, err := s.db.GetLastBundleNumber(r.Context())
	if err != nil {
		resp.error("bundle not found", http.StatusNotFound)
		return
	}

	if bundleNum == lastBundle+1 {
		// This is the upcoming bundle - return preview based on mempool
		upcomingBundle, err := s.createUpcomingBundlePreview(r.Context(), r, bundleNum)
		if err != nil {
			resp.error(fmt.Sprintf("failed to create upcoming bundle preview: %v", err), http.StatusInternalServerError)
			return
		}
		resp.json(upcomingBundle)
		return
	}

	// Not an upcoming bundle, just not found
	resp.error("bundle not found", http.StatusNotFound)
}

func (s *Server) createUpcomingBundlePreview(ctx context.Context, r *http.Request, bundleNum int) (map[string]interface{}, error) {
	// Get mempool stats
	mempoolCount, err := s.db.GetMempoolCount(ctx)
	if err != nil {
		return nil, err
	}

	if mempoolCount == 0 {
		return map[string]interface{}{
			"plc_bundle_number": bundleNum,
			"is_upcoming":       true,
			"status":            "empty",
			"message":           "No operations in mempool yet",
			"operation_count":   0,
		}, nil
	}

	// Get first and last operations for time range
	firstOp, err := s.db.GetFirstMempoolOperation(ctx)
	if err != nil {
		return nil, err
	}

	lastOp, err := s.db.GetLastMempoolOperation(ctx)
	if err != nil {
		return nil, err
	}

	// Get unique DID count
	uniqueDIDCount, err := s.db.GetMempoolUniqueDIDCount(ctx)
	if err != nil {
		return nil, err
	}

	// Get uncompressed size estimate
	uncompressedSize, err := s.db.GetMempoolUncompressedSize(ctx)
	if err != nil {
		return nil, err
	}

	// Estimate compressed size (typical ratio is ~0.1-0.15 for PLC data)
	estimatedCompressedSize := int64(float64(uncompressedSize) * 0.12)

	// Calculate completion estimate
	var estimatedCompletionTime *time.Time
	var operationsNeeded int
	var currentRate float64

	operationsNeeded = plc.BUNDLE_SIZE - mempoolCount

	if mempoolCount < plc.BUNDLE_SIZE && mempoolCount > 0 {
		timeSpan := lastOp.CreatedAt.Sub(firstOp.CreatedAt).Seconds()
		if timeSpan > 0 {
			currentRate = float64(mempoolCount) / timeSpan
			if currentRate > 0 {
				secondsNeeded := float64(operationsNeeded) / currentRate
				completionTime := time.Now().Add(time.Duration(secondsNeeded) * time.Second)
				estimatedCompletionTime = &completionTime
			}
		}
	}

	// Get previous bundle for cursor context
	var prevBundleHash string
	var cursor string
	if bundleNum > 1 {
		prevBundle, err := s.db.GetBundleByNumber(ctx, bundleNum-1)
		if err == nil {
			prevBundleHash = prevBundle.Hash
			cursor = prevBundle.EndTime.Format(time.RFC3339Nano)
		}
	}

	// Determine bundle status
	status := "filling"
	if mempoolCount >= plc.BUNDLE_SIZE {
		status = "ready"
	}

	// Build upcoming bundle response
	result := map[string]interface{}{
		"plc_bundle_number":         bundleNum,
		"is_upcoming":               true,
		"status":                    status,
		"operation_count":           mempoolCount,
		"target_operation_count":    plc.BUNDLE_SIZE,
		"progress_percent":          float64(mempoolCount) / float64(plc.BUNDLE_SIZE) * 100,
		"operations_needed":         operationsNeeded,
		"did_count":                 uniqueDIDCount,
		"start_time":                firstOp.CreatedAt, // This is FIXED once first op exists
		"current_end_time":          lastOp.CreatedAt,  // This will change as more ops arrive
		"uncompressed_size":         uncompressedSize,
		"estimated_compressed_size": estimatedCompressedSize,
		"compression_ratio":         float64(uncompressedSize) / float64(estimatedCompressedSize),
		"prev_bundle_hash":          prevBundleHash,
		"cursor":                    cursor,
	}

	if estimatedCompletionTime != nil {
		result["estimated_completion_time"] = *estimatedCompletionTime
		result["current_rate_per_second"] = currentRate
	}

	// Get actual mempool operations if requested
	if r.URL.Query().Get("include_dids") == "true" {
		ops, err := s.db.GetMempoolOperations(ctx, plc.BUNDLE_SIZE)
		if err == nil {
			// Extract unique DIDs
			didSet := make(map[string]bool)
			for _, op := range ops {
				didSet[op.DID] = true
			}
			dids := make([]string, 0, len(didSet))
			for did := range didSet {
				dids = append(dids, did)
			}
			result["dids"] = dids
		}
	}

	return result, nil
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
	if err == nil {
		// Bundle exists, serve it normally
		resp.bundleHeaders(bundle)

		if compressed {
			s.serveCompressedBundle(w, r, bundle)
		} else {
			s.serveUncompressedBundle(w, r, bundle)
		}
		return
	}

	// Bundle not found - check if it's the upcoming bundle
	lastBundle, err := s.db.GetLastBundleNumber(r.Context())
	if err != nil {
		resp.error("bundle not found", http.StatusNotFound)
		return
	}

	if bundleNum == lastBundle+1 {
		// This is the upcoming bundle - serve from mempool
		s.serveUpcomingBundle(w, r, bundleNum)
		return
	}

	// Not an upcoming bundle, just not found
	resp.error("bundle not found", http.StatusNotFound)
}

func (s *Server) serveUpcomingBundle(w http.ResponseWriter, r *http.Request, bundleNum int) {
	ctx := r.Context()

	// Get mempool count
	mempoolCount, err := s.db.GetMempoolCount(ctx)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get mempool count: %v", err), http.StatusInternalServerError)
		return
	}

	if mempoolCount == 0 {
		http.Error(w, "upcoming bundle is empty (no operations in mempool)", http.StatusNotFound)
		return
	}

	// Get mempool operations (up to BUNDLE_SIZE)
	mempoolOps, err := s.db.GetMempoolOperations(ctx, plc.BUNDLE_SIZE)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get mempool operations: %v", err), http.StatusInternalServerError)
		return
	}

	if len(mempoolOps) == 0 {
		http.Error(w, "upcoming bundle is empty", http.StatusNotFound)
		return
	}

	// Get time range
	firstOp := mempoolOps[0]
	lastOp := mempoolOps[len(mempoolOps)-1]

	// Extract unique DIDs
	didSet := make(map[string]bool)
	for _, op := range mempoolOps {
		didSet[op.DID] = true
	}

	// Get previous bundle hash
	prevBundleHash := ""
	if bundleNum > 1 {
		if prevBundle, err := s.db.GetBundleByNumber(ctx, bundleNum-1); err == nil {
			prevBundleHash = prevBundle.Hash
		}
	}

	// Serialize operations to JSONL
	var buf []byte
	for _, mop := range mempoolOps {
		buf = append(buf, []byte(mop.Operation)...)
		buf = append(buf, '\n')
	}

	// Calculate size
	uncompressedSize := int64(len(buf))

	// Set headers
	w.Header().Set("X-Bundle-Number", fmt.Sprintf("%d", bundleNum))
	w.Header().Set("X-Bundle-Is-Upcoming", "true")
	w.Header().Set("X-Bundle-Status", "preview")
	w.Header().Set("X-Bundle-Start-Time", firstOp.CreatedAt.Format(time.RFC3339Nano))
	w.Header().Set("X-Bundle-Current-End-Time", lastOp.CreatedAt.Format(time.RFC3339Nano))
	w.Header().Set("X-Bundle-Operation-Count", fmt.Sprintf("%d", len(mempoolOps)))
	w.Header().Set("X-Bundle-Target-Count", fmt.Sprintf("%d", plc.BUNDLE_SIZE))
	w.Header().Set("X-Bundle-Progress-Percent", fmt.Sprintf("%.2f", float64(len(mempoolOps))/float64(plc.BUNDLE_SIZE)*100))
	w.Header().Set("X-Bundle-DID-Count", fmt.Sprintf("%d", len(didSet)))
	w.Header().Set("X-Bundle-Prev-Hash", prevBundleHash)

	w.Header().Set("Content-Type", "application/jsonl")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%06d-upcoming.jsonl", bundleNum))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", uncompressedSize))
	w.Header().Set("X-Uncompressed-Size", fmt.Sprintf("%d", uncompressedSize))

	w.WriteHeader(http.StatusOK)
	w.Write(buf)
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

func (s *Server) handleGetCountryLeaderboard(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)

	stats, err := s.db.GetCountryLeaderboard(r.Context())
	if err != nil {
		resp.error(err.Error(), http.StatusInternalServerError)
		return
	}

	resp.json(stats)
}

func (s *Server) handleGetVersionStats(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)

	stats, err := s.db.GetVersionStats(r.Context())
	if err != nil {
		resp.error(err.Error(), http.StatusInternalServerError)
		return
	}

	// Add summary totals
	var totalPDS int64
	var totalUsers int64
	for _, stat := range stats {
		totalPDS += stat.PDSCount
		totalUsers += stat.TotalUsers
	}

	result := map[string]interface{}{
		"versions": stats,
		"summary": map[string]interface{}{
			"total_pds_with_version": totalPDS,
			"total_users":            totalUsers,
			"version_count":          len(stats),
		},
	}

	resp.json(result)
}

// ===== HEALTH HANDLER =====

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	newResponse(w).json(map[string]string{"status": "ok"})
}

func (s *Server) handleGetJobStatus(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)
	tracker := monitor.GetTracker()

	jobs := tracker.GetAllJobs()

	result := make(map[string]interface{})
	for name, job := range jobs {
		jobData := map[string]interface{}{
			"name":          job.Name,
			"status":        job.Status,
			"run_count":     job.RunCount,
			"success_count": job.SuccessCount,
			"error_count":   job.ErrorCount,
		}

		if !job.LastRun.IsZero() {
			jobData["last_run"] = job.LastRun
			jobData["last_duration"] = job.Duration.String()
		}

		if !job.NextRun.IsZero() {
			jobData["next_run"] = job.NextRun
			jobData["next_run_in"] = time.Until(job.NextRun).Round(time.Second).String()
		}

		if job.Status == "running" {
			jobData["running_for"] = job.Duration.Round(time.Second).String()

			if job.Progress != nil {
				jobData["progress"] = job.Progress
			}

			// Add worker status
			workers := tracker.GetWorkers(name)
			if len(workers) > 0 {
				jobData["workers"] = workers
			}
		}

		if job.Error != "" {
			jobData["error"] = job.Error
		}

		result[name] = jobData
	}

	resp.json(result)
}

func (s *Server) handleGetDuplicateEndpoints(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)

	duplicates, err := s.db.GetDuplicateEndpoints(r.Context())
	if err != nil {
		resp.error(err.Error(), http.StatusInternalServerError)
		return
	}

	// Format response
	result := make([]map[string]interface{}, 0)
	for serverDID, endpoints := range duplicates {
		result = append(result, map[string]interface{}{
			"server_did":    serverDID,
			"primary":       endpoints[0],  // First discovered
			"aliases":       endpoints[1:], // Other domains
			"alias_count":   len(endpoints) - 1,
			"total_domains": len(endpoints),
		})
	}

	resp.json(map[string]interface{}{
		"duplicates":              result,
		"total_duplicate_servers": len(duplicates),
	})
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

func normalizeEndpoint(endpoint string) string {
	endpoint = strings.TrimPrefix(endpoint, "https://")
	endpoint = strings.TrimPrefix(endpoint, "http://")
	endpoint = strings.TrimSuffix(endpoint, "/")
	return endpoint
}
