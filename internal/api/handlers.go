package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/atscan/atscand/internal/log"
	"github.com/atscan/atscand/internal/monitor"
	"github.com/atscan/atscand/internal/plc"
	"github.com/atscan/atscand/internal/storage"
	"github.com/atscan/plcbundle"
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

func (r *response) bundleHeaders(bundle *plcbundle.BundleMetadata) {
	r.w.Header().Set("X-Bundle-Number", fmt.Sprintf("%d", bundle.BundleNumber))
	r.w.Header().Set("X-Bundle-Hash", bundle.Hash)
	r.w.Header().Set("X-Bundle-Compressed-Hash", bundle.CompressedHash)
	r.w.Header().Set("X-Bundle-Start-Time", bundle.StartTime.Format(time.RFC3339Nano))
	r.w.Header().Set("X-Bundle-End-Time", bundle.EndTime.Format(time.RFC3339Nano))
	r.w.Header().Set("X-Bundle-Operation-Count", fmt.Sprintf("%d", plc.BUNDLE_SIZE))
	r.w.Header().Set("X-Bundle-DID-Count", fmt.Sprintf("%d", bundle.DIDCount))
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

func formatEndpointResponse(ep *storage.Endpoint) map[string]interface{} {
	response := map[string]interface{}{
		"id":            ep.ID,
		"endpoint_type": ep.EndpointType,
		"endpoint":      ep.Endpoint,
		"discovered_at": ep.DiscoveredAt,
		"last_checked":  ep.LastChecked,
		"status":        statusToString(ep.Status),
	}

	// Add IPs if available
	if ep.IP != "" {
		response["ip"] = ep.IP
	}
	if ep.IPv6 != "" {
		response["ipv6"] = ep.IPv6
	}

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

// handleGetRandomEndpoint returns a random endpoint of specified type
func (s *Server) handleGetRandomEndpoint(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)

	// Get required type parameter
	endpointType := r.URL.Query().Get("type")
	if endpointType == "" {
		resp.error("type parameter is required", http.StatusBadRequest)
		return
	}

	// Get optional status parameter
	status := r.URL.Query().Get("status")

	filter := &storage.EndpointFilter{
		Type:   endpointType,
		Status: status,
		Random: true,
		Limit:  1,
		Offset: 0,
	}

	endpoints, err := s.db.GetEndpoints(r.Context(), filter)
	if err != nil {
		resp.error(err.Error(), http.StatusInternalServerError)
		return
	}

	if len(endpoints) == 0 {
		resp.error("no endpoints found matching criteria", http.StatusNotFound)
		return
	}

	resp.json(formatEndpointResponse(endpoints[0]))
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

	// Add IPs if available
	if pds.IP != "" {
		response["ip"] = pds.IP
	}
	if pds.IPv6 != "" {
		response["ipv6"] = pds.IPv6
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

		// Add all network type flags
		response["is_datacenter"] = pds.IPInfo.IsDatacenter
		response["is_vpn"] = pds.IPInfo.IsVPN
		response["is_crawler"] = pds.IPInfo.IsCrawler
		response["is_tor"] = pds.IPInfo.IsTor
		response["is_proxy"] = pds.IPInfo.IsProxy

		// Add computed is_home field
		response["is_home"] = pds.IPInfo.IsHome()
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

	// Add full IP info with computed is_home field
	if pds.IPInfo != nil {
		// Convert IPInfo to map
		ipInfoMap := make(map[string]interface{})
		ipInfoJSON, _ := json.Marshal(pds.IPInfo)
		json.Unmarshal(ipInfoJSON, &ipInfoMap)

		// Add computed is_home field
		ipInfoMap["is_home"] = pds.IPInfo.IsHome()

		response["ip_info"] = ipInfoMap
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

		if scan.Status != storage.EndpointStatusOnline && scan.ScanData != nil && scan.ScanData.Metadata != nil {
			if errorMsg, ok := scan.ScanData.Metadata["error"].(string); ok && errorMsg != "" {
				scanMap["error"] = errorMsg
			}
		}

		if scan.ResponseTime > 0 {
			scanMap["response_time"] = scan.ResponseTime
		}

		if scan.Version != "" {
			scanMap["version"] = scan.Version
		}

		if scan.UsedIP != "" {
			scanMap["used_ip"] = scan.UsedIP
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

// Get repos for a specific PDS
func (s *Server) handleGetPDSRepos(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)
	vars := mux.Vars(r)
	endpoint := "https://" + normalizeEndpoint(vars["endpoint"])

	pds, err := s.db.GetPDSDetail(r.Context(), endpoint)
	if err != nil {
		resp.error("PDS not found", http.StatusNotFound)
		return
	}

	// Parse query parameters
	activeOnly := r.URL.Query().Get("active") == "true"
	limit := getQueryInt(r, "limit", 100)
	offset := getQueryInt(r, "offset", 0)

	// Cap limit at 1000
	if limit > 1000 {
		limit = 1000
	}

	repos, err := s.db.GetPDSRepos(r.Context(), pds.ID, activeOnly, limit, offset)
	if err != nil {
		resp.error(err.Error(), http.StatusInternalServerError)
		return
	}

	// Get total from latest scan (same as user_count)
	totalRepos := 0
	if pds.LatestScan != nil {
		totalRepos = pds.LatestScan.UserCount
	}

	resp.json(map[string]interface{}{
		"endpoint":    pds.Endpoint,
		"total_repos": totalRepos,
		"returned":    len(repos),
		"limit":       limit,
		"offset":      offset,
		"repos":       repos,
	})
}

// Find which PDS hosts a specific DID
func (s *Server) handleGetDIDRepos(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)
	vars := mux.Vars(r)
	did := vars["did"]

	repos, err := s.db.GetReposByDID(r.Context(), did)
	if err != nil {
		resp.error(err.Error(), http.StatusInternalServerError)
		return
	}

	resp.json(map[string]interface{}{
		"did":        did,
		"pds_count":  len(repos),
		"hosting_on": repos,
	})
}

// Add to internal/api/handlers.go
func (s *Server) handleGetPDSRepoStats(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)
	vars := mux.Vars(r)
	endpoint := "https://" + normalizeEndpoint(vars["endpoint"])

	pds, err := s.db.GetPDSDetail(r.Context(), endpoint)
	if err != nil {
		resp.error("PDS not found", http.StatusNotFound)
		return
	}

	stats, err := s.db.GetPDSRepoStats(r.Context(), pds.ID)
	if err != nil {
		resp.error(err.Error(), http.StatusInternalServerError)
		return
	}

	resp.json(stats)
}

// ===== GLOBAL DID HANDLER =====

// handleGetGlobalDID provides a consolidated view of a DID
func (s *Server) handleGetGlobalDID(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)
	vars := mux.Vars(r)
	did := vars["did"]
	ctx := r.Context()

	// Get DID info (now includes handle and pds from database)
	didInfo, err := s.db.GetGlobalDIDInfo(ctx, did)
	if err != nil {
		if err == sql.ErrNoRows {
			if !s.plcIndexDIDs {
				resp.error("DID not found. Note: DID indexing is disabled in configuration.", http.StatusNotFound)
			} else {
				resp.error("DID not found in PLC index.", http.StatusNotFound)
			}
		} else {
			resp.error(err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// Optionally include latest operation details if requested
	var latestOperation *plc.PLCOperation
	if r.URL.Query().Get("include_operation") == "true" && len(didInfo.BundleNumbers) > 0 {
		lastBundleNum := didInfo.BundleNumbers[len(didInfo.BundleNumbers)-1]
		ops, err := s.bundleManager.LoadBundleOperations(ctx, lastBundleNum)
		if err != nil {
			log.Error("Failed to load bundle %d for DID %s: %v", lastBundleNum, did, err)
		} else {
			// Find latest operation for this DID (in reverse)
			for i := len(ops) - 1; i >= 0; i-- {
				if ops[i].DID == did {
					latestOperation = &ops[i]
					break
				}
			}
		}
	}

	result := map[string]interface{}{
		"did":                  didInfo.DID,
		"handle":               didInfo.Handle,     // From database!
		"current_pds":          didInfo.CurrentPDS, // From database!
		"plc_index_created_at": didInfo.CreatedAt,
		"plc_bundle_history":   didInfo.BundleNumbers,
		"pds_hosting_on":       didInfo.HostingOn,
	}

	// Only include operation if requested
	if latestOperation != nil {
		result["latest_plc_operation"] = latestOperation
	}

	resp.json(result)
}

// handleGetDIDByHandle resolves a handle to a DID
func (s *Server) handleGetDIDByHandle(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)
	vars := mux.Vars(r)
	handle := vars["handle"]

	// Normalize handle (remove @ prefix if present)
	handle = strings.TrimPrefix(handle, "@")

	// Look up DID by handle
	didRecord, err := s.db.GetDIDByHandle(r.Context(), handle)
	if err != nil {
		if err == sql.ErrNoRows {
			if !s.plcIndexDIDs {
				resp.error("Handle not found. Note: DID indexing is disabled in configuration.", http.StatusNotFound)
			} else {
				resp.error("Handle not found.", http.StatusNotFound)
			}
		} else {
			resp.error(err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// Return just the handle and DID
	resp.json(map[string]string{
		"handle": handle,
		"did":    didRecord.DID,
	})
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

	lastBundle := s.bundleManager.GetLastBundleNumber()
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

	// Get from library's index
	index := s.bundleManager.GetIndex()
	bundleMeta, err := index.GetBundle(bundleNum)
	if err != nil {
		// Check if it's upcoming bundle
		lastBundle := index.GetLastBundle()
		if lastBundle != nil && bundleNum == lastBundle.BundleNumber+1 {
			upcomingBundle, err := s.createUpcomingBundlePreview(bundleNum)
			if err != nil {
				resp.error(err.Error(), http.StatusInternalServerError)
				return
			}
			resp.json(upcomingBundle)
			return
		}
		resp.error("bundle not found", http.StatusNotFound)
		return
	}

	resp.json(formatBundleMetadata(bundleMeta))
}

// Helper to format library's BundleMetadata
func formatBundleMetadata(meta *plcbundle.BundleMetadata) map[string]interface{} {
	return map[string]interface{}{
		"plc_bundle_number": meta.BundleNumber,
		"start_time":        meta.StartTime,
		"end_time":          meta.EndTime,
		"operation_count":   meta.OperationCount,
		"did_count":         meta.DIDCount,
		"hash":              meta.Hash,        // Chain hash (primary)
		"content_hash":      meta.ContentHash, // Content hash
		"parent":            meta.Parent,      // Parent chain hash
		"compressed_hash":   meta.CompressedHash,
		"compressed_size":   meta.CompressedSize,
		"uncompressed_size": meta.UncompressedSize,
		"compression_ratio": float64(meta.UncompressedSize) / float64(meta.CompressedSize),
		"cursor":            meta.Cursor,
		"created_at":        meta.CreatedAt,
	}
}

func (s *Server) createUpcomingBundlePreview(bundleNum int) (map[string]interface{}, error) {
	// Get mempool stats from library via wrapper
	stats := s.bundleManager.GetMempoolStats()

	count, ok := stats["count"].(int)
	if !ok || count == 0 {
		return map[string]interface{}{
			"plc_bundle_number": bundleNum,
			"is_upcoming":       true,
			"status":            "empty",
			"message":           "No operations in mempool yet",
			"operation_count":   0,
		}, nil
	}

	// Build response
	result := map[string]interface{}{
		"plc_bundle_number":      bundleNum,
		"is_upcoming":            true,
		"status":                 "filling",
		"operation_count":        count,
		"did_count":              stats["did_count"],
		"target_operation_count": 10000,
		"progress_percent":       float64(count) / 100.0,
		"operations_needed":      10000 - count,
	}

	if count >= 10000 {
		result["status"] = "ready"
	}

	// Add time range if available
	if firstTime, ok := stats["first_time"]; ok {
		result["start_time"] = firstTime
	}
	if lastTime, ok := stats["last_time"]; ok {
		result["current_end_time"] = lastTime
	}

	// Add size info if available
	if sizeBytes, ok := stats["size_bytes"]; ok {
		result["uncompressed_size"] = sizeBytes
		result["estimated_compressed_size"] = int64(float64(sizeBytes.(int)) * 0.12)
	}

	// Get previous bundle info
	if bundleNum > 1 {
		if prevBundle, err := s.bundleManager.GetBundleMetadata(bundleNum - 1); err == nil {
			result["parent"] = prevBundle.Hash // Parent chain hash
			result["cursor"] = prevBundle.EndTime.Format(time.RFC3339Nano)
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

	// Get from library
	dids, didCount, err := s.bundleManager.GetDIDsForBundle(r.Context(), bundleNum)
	if err != nil {
		resp.error("bundle not found", http.StatusNotFound)
		return
	}

	resp.json(map[string]interface{}{
		"plc_bundle_number": bundleNum,
		"did_count":         didCount,
		"dids":              dids,
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

	bundle, err := s.bundleManager.GetBundleMetadata(bundleNum)
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
	lastBundle := s.bundleManager.GetLastBundleNumber()
	if bundleNum == lastBundle+1 {
		// This is the upcoming bundle - serve from mempool
		s.serveUpcomingBundle(w, bundleNum)
		return
	}

	// Not an upcoming bundle, just not found
	resp.error("bundle not found", http.StatusNotFound)
}

func (s *Server) serveUpcomingBundle(w http.ResponseWriter, bundleNum int) {
	// Get mempool stats
	stats := s.bundleManager.GetMempoolStats()
	count, ok := stats["count"].(int)

	if !ok || count == 0 {
		http.Error(w, "upcoming bundle is empty (no operations in mempool)", http.StatusNotFound)
		return
	}

	// Get operations from mempool
	ops, err := s.bundleManager.GetMempoolOperations()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get mempool operations: %v", err), http.StatusInternalServerError)
		return
	}

	if len(ops) == 0 {
		http.Error(w, "no operations in mempool", http.StatusNotFound)
		return
	}

	// Calculate times
	firstOp := ops[0]
	lastOp := ops[len(ops)-1]

	// Extract unique DIDs
	didSet := make(map[string]bool)
	for _, op := range ops {
		didSet[op.DID] = true
	}

	// Calculate uncompressed size
	uncompressedSize := int64(0)
	for _, op := range ops {
		uncompressedSize += int64(len(op.RawJSON)) + 1 // +1 for newline
	}

	// Get previous bundle hash
	prevBundleHash := ""
	if bundleNum > 1 {
		if prevBundle, err := s.bundleManager.GetBundleMetadata(bundleNum - 1); err == nil {
			prevBundleHash = prevBundle.Hash
		}
	}

	// Set headers
	w.Header().Set("X-Bundle-Number", fmt.Sprintf("%d", bundleNum))
	w.Header().Set("X-Bundle-Is-Upcoming", "true")
	w.Header().Set("X-Bundle-Status", "preview")
	w.Header().Set("X-Bundle-Start-Time", firstOp.CreatedAt.Format(time.RFC3339Nano))
	w.Header().Set("X-Bundle-Current-End-Time", lastOp.CreatedAt.Format(time.RFC3339Nano))
	w.Header().Set("X-Bundle-Operation-Count", fmt.Sprintf("%d", len(ops)))
	w.Header().Set("X-Bundle-Target-Count", "10000")
	w.Header().Set("X-Bundle-Progress-Percent", fmt.Sprintf("%.2f", float64(len(ops))/100.0))
	w.Header().Set("X-Bundle-DID-Count", fmt.Sprintf("%d", len(didSet)))
	w.Header().Set("X-Bundle-Prev-Hash", prevBundleHash)
	w.Header().Set("X-Uncompressed-Size", fmt.Sprintf("%d", uncompressedSize))

	w.Header().Set("Content-Type", "application/jsonl")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%06d-upcoming.jsonl", bundleNum))

	// Stream operations as JSONL
	w.WriteHeader(http.StatusOK)

	for _, op := range ops {
		// Use RawJSON if available (preserves exact format)
		if len(op.RawJSON) > 0 {
			w.Write(op.RawJSON)
		} else {
			// Fallback to marshaling
			data, _ := json.Marshal(op)
			w.Write(data)
		}
		w.Write([]byte("\n"))
	}
}

func (s *Server) serveCompressedBundle(w http.ResponseWriter, r *http.Request, bundle *plcbundle.BundleMetadata) {
	resp := newResponse(w)

	// Use the new streaming API for compressed data
	reader, err := s.bundleManager.StreamRaw(r.Context(), bundle.BundleNumber)
	if err != nil {
		resp.error(fmt.Sprintf("error streaming compressed bundle: %v", err), http.StatusInternalServerError)
		return
	}
	defer reader.Close()

	w.Header().Set("Content-Type", "application/zstd")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%06d.jsonl.zst", bundle.BundleNumber))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", bundle.CompressedSize))
	w.Header().Set("X-Compressed-Size", fmt.Sprintf("%d", bundle.CompressedSize))

	// Stream the data directly to the response
	w.WriteHeader(http.StatusOK)
	io.Copy(w, reader)
}

func (s *Server) serveUncompressedBundle(w http.ResponseWriter, r *http.Request, bundle *plcbundle.BundleMetadata) {
	resp := newResponse(w)

	// Use the new streaming API for decompressed data
	reader, err := s.bundleManager.StreamDecompressed(r.Context(), bundle.BundleNumber)
	if err != nil {
		resp.error(fmt.Sprintf("error streaming decompressed bundle: %v", err), http.StatusInternalServerError)
		return
	}
	defer reader.Close()

	w.Header().Set("Content-Type", "application/jsonl")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%06d.jsonl", bundle.BundleNumber))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", bundle.UncompressedSize))
	w.Header().Set("X-Compressed-Size", fmt.Sprintf("%d", bundle.CompressedSize))
	w.Header().Set("X-Uncompressed-Size", fmt.Sprintf("%d", bundle.UncompressedSize))
	if bundle.CompressedSize > 0 {
		w.Header().Set("X-Compression-Ratio", fmt.Sprintf("%.2f", float64(bundle.UncompressedSize)/float64(bundle.CompressedSize)))
	}

	// Stream the data directly to the response
	w.WriteHeader(http.StatusOK)
	io.Copy(w, reader)
}

func (s *Server) handleGetPLCBundles(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)
	limit := getQueryInt(r, "limit", 50)

	bundles := s.bundleManager.GetBundles(limit)

	response := make([]map[string]interface{}, len(bundles))
	for i, bundle := range bundles {
		response[i] = formatBundleMetadata(bundle)
	}

	resp.json(response)
}

func (s *Server) handleGetPLCBundleStats(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)

	stats := s.bundleManager.GetBundleStats()

	bundleCount := stats["bundle_count"].(int64)
	totalSize := stats["total_size"].(int64)
	totalUncompressedSize := stats["total_uncompressed_size"].(int64)
	lastBundle := stats["last_bundle"].(int64)

	resp.json(map[string]interface{}{
		"plc_bundle_count":          bundleCount,
		"last_bundle_number":        lastBundle,
		"total_compressed_size":     totalSize,
		"total_uncompressed_size":   totalUncompressedSize,
		"overall_compression_ratio": float64(totalUncompressedSize) / float64(totalSize),
	})
}

// ===== MEMPOOL HANDLERS =====

func (s *Server) handleGetMempoolStats(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)

	// Get stats from library's mempool via wrapper method
	stats := s.bundleManager.GetMempoolStats()

	// Convert to API response format
	result := map[string]interface{}{
		"operation_count":   stats["count"],
		"can_create_bundle": stats["can_create_bundle"],
	}

	// Add size information
	if sizeBytes, ok := stats["size_bytes"]; ok {
		result["uncompressed_size"] = sizeBytes
		result["uncompressed_size_mb"] = float64(sizeBytes.(int)) / 1024 / 1024
	}

	// Add time range and calculate estimated completion
	if count, ok := stats["count"].(int); ok && count > 0 {
		if firstTime, ok := stats["first_time"].(time.Time); ok {
			result["mempool_start_time"] = firstTime

			if lastTime, ok := stats["last_time"].(time.Time); ok {
				result["mempool_end_time"] = lastTime

				// Calculate estimated next bundle time if not complete
				if count < 10000 {
					timeSpan := lastTime.Sub(firstTime).Seconds()
					if timeSpan > 0 {
						opsPerSecond := float64(count) / timeSpan
						if opsPerSecond > 0 {
							remainingOps := 10000 - count
							secondsNeeded := float64(remainingOps) / opsPerSecond
							estimatedTime := time.Now().Add(time.Duration(secondsNeeded) * time.Second)

							result["estimated_next_bundle_time"] = estimatedTime
							result["current_rate_per_second"] = opsPerSecond
							result["operations_needed"] = remainingOps
						}
					}
					result["progress_percent"] = float64(count) / 100.0
				} else {
					// Ready to create bundle
					result["estimated_next_bundle_time"] = time.Now()
					result["operations_needed"] = 0
				}
			}
		}
	} else {
		// Empty mempool
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

func (s *Server) handleVerifyChain(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)

	lastBundle := s.bundleManager.GetLastBundleNumber()
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
		bundle, err := s.bundleManager.GetBundleMetadata(i)
		if err != nil {
			valid = false
			brokenAt = i
			errorMsg = fmt.Sprintf("Bundle %06d not found", i)
			break
		}

		if i > 1 {
			prevBundle, err := s.bundleManager.GetBundleMetadata(i - 1)
			if err != nil {
				valid = false
				brokenAt = i
				errorMsg = fmt.Sprintf("Previous bundle %06d not found", i-1)
				break
			}

			if bundle.Parent != prevBundle.Hash {
				valid = false
				brokenAt = i
				errorMsg = fmt.Sprintf("Chain broken: bundle %06d parent doesn't match bundle %06d hash", i, i-1)
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

	lastBundle := s.bundleManager.GetLastBundleNumber()
	if lastBundle == 0 {
		resp.json(map[string]interface{}{
			"chain_length": 0,
			"status":       "empty",
		})
		return
	}

	firstBundle, _ := s.bundleManager.GetBundleMetadata(1)
	lastBundleData, _ := s.bundleManager.GetBundleMetadata(lastBundle)
	stats := s.bundleManager.GetBundleStats()

	resp.json(map[string]interface{}{
		"chain_length":             lastBundle,
		"total_bundles":            stats["bundle_count"],
		"total_compressed_size":    stats["total_size"],
		"total_compressed_size_mb": float64(stats["total_size"].(int64)) / 1024 / 1024,
		"chain_start_time":         firstBundle.StartTime,
		"chain_end_time":           lastBundleData.EndTime,
		"chain_head_hash":          lastBundleData.Hash,
		"first_parent":             firstBundle.Parent,
		"last_parent":              lastBundleData.Parent,
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

	startBundle := s.findStartBundle(afterTime)
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

func (s *Server) findStartBundle(afterTime time.Time) int {
	if afterTime.IsZero() {
		return 1
	}

	foundBundle := s.bundleManager.FindBundleForTimestamp(afterTime)
	if foundBundle > 1 {
		return foundBundle - 1
	}
	return foundBundle
}

func (s *Server) collectOperations(ctx context.Context, startBundle int, afterTime time.Time, count int) []plc.PLCOperation {
	var allOps []plc.PLCOperation
	seenCIDs := make(map[string]bool)

	lastBundle := s.bundleManager.GetLastBundleNumber()

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

func (s *Server) handleGetPLCHistory(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)

	limit := getQueryInt(r, "limit", 0)
	fromBundle := getQueryInt(r, "from", 1)

	// Use BundleManager instead of database
	history, err := s.bundleManager.GetPLCHistory(r.Context(), limit, fromBundle)
	if err != nil {
		resp.error(err.Error(), http.StatusInternalServerError)
		return
	}

	var totalOps int64
	var totalUncompressed int64
	var totalCompressed int64

	for _, point := range history {
		totalOps += int64(point.OperationCount)
		totalUncompressed += point.UncompressedSize
		totalCompressed += point.CompressedSize
	}

	result := map[string]interface{}{
		"data": history,
		"summary": map[string]interface{}{
			"days":               len(history),
			"total_operations":   totalOps,
			"total_uncompressed": totalUncompressed,
			"total_compressed":   totalCompressed,
			"compression_ratio":  0.0,
		},
	}

	if len(history) > 0 {
		result["summary"].(map[string]interface{})["first_date"] = history[0].Date
		result["summary"].(map[string]interface{})["last_date"] = history[len(history)-1].Date
		result["summary"].(map[string]interface{})["time_span_days"] = len(history)

		if totalCompressed > 0 {
			result["summary"].(map[string]interface{})["compression_ratio"] = float64(totalUncompressed) / float64(totalCompressed)
		}

		result["summary"].(map[string]interface{})["avg_operations_per_day"] = totalOps / int64(len(history))
		result["summary"].(map[string]interface{})["avg_size_per_day"] = totalUncompressed / int64(len(history))
	}

	resp.json(result)
}

// ===== DEBUG HANDLERS =====

func (s *Server) handleGetDBSizes(w http.ResponseWriter, r *http.Request) {
	resp := newResponse(w)
	ctx := r.Context()
	schema := "public" // Or make configurable if needed

	tableSizes, err := s.db.GetTableSizes(ctx, schema)
	if err != nil {
		log.Error("Failed to get table sizes: %v", err)
		resp.error("Failed to retrieve table sizes", http.StatusInternalServerError)
		return
	}

	indexSizes, err := s.db.GetIndexSizes(ctx, schema)
	if err != nil {
		log.Error("Failed to get index sizes: %v", err)
		resp.error("Failed to retrieve index sizes", http.StatusInternalServerError)
		return
	}

	resp.json(map[string]interface{}{
		"schema":      schema,
		"tables":      tableSizes,
		"indexes":     indexSizes,
		"retrievedAt": time.Now().UTC(),
	})
}

// ===== UTILITY FUNCTIONS =====

func normalizeEndpoint(endpoint string) string {
	endpoint = strings.TrimPrefix(endpoint, "https://")
	endpoint = strings.TrimPrefix(endpoint, "http://")
	endpoint = strings.TrimSuffix(endpoint, "/")
	return endpoint
}
