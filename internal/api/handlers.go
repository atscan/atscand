package api

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/atscan/atscanner/internal/log"
	"github.com/atscan/atscanner/internal/plc"
	"github.com/atscan/atscanner/internal/storage"
	"github.com/gorilla/mux"
	"github.com/klauspost/compress/zstd"
)

func (s *Server) handleGetPDSList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	filter := &storage.PDSFilter{}

	if status := r.URL.Query().Get("status"); status != "" {
		filter.Status = status
	}

	if limit := r.URL.Query().Get("limit"); limit != "" {
		if l, err := strconv.Atoi(limit); err == nil {
			filter.Limit = l
		}
	}

	if offset := r.URL.Query().Get("offset"); offset != "" {
		if o, err := strconv.Atoi(offset); err == nil {
			filter.Offset = o
		}
	}

	servers, err := s.db.GetPDSServers(ctx, filter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Convert status codes to strings for API
	response := make([]map[string]interface{}, len(servers))
	for i, srv := range servers {
		response[i] = map[string]interface{}{
			"id":            srv.ID,
			"endpoint":      srv.Endpoint,
			"discovered_at": srv.DiscoveredAt,
			"last_checked":  srv.LastChecked,
			"status":        statusToString(srv.Status),
			"user_count":    srv.UserCount,
		}
	}

	respondJSON(w, response)
}

func (s *Server) handleGetPDS(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	endpoint := vars["endpoint"]

	pds, err := s.db.GetPDS(ctx, endpoint)
	if err != nil {
		http.Error(w, "PDS not found", http.StatusNotFound)
		return
	}

	// Get recent scans
	scans, _ := s.db.GetPDSScans(ctx, pds.ID, 10)

	response := map[string]interface{}{
		"id":            pds.ID,
		"endpoint":      pds.Endpoint,
		"discovered_at": pds.DiscoveredAt,
		"last_checked":  pds.LastChecked,
		"status":        statusToString(pds.Status),
		"user_count":    pds.UserCount,
		"recent_scans":  scans,
	}

	respondJSON(w, response)
}

func (s *Server) handleGetPDSStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	stats, err := s.db.GetPDSStats(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	respondJSON(w, stats)
}

func (s *Server) handleGetDID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	did := vars["did"]

	bundles, err := s.db.GetBundlesForDID(ctx, did)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if len(bundles) == 0 {
		http.Error(w, "DID not found in bundles", http.StatusNotFound)
		return
	}

	lastBundle := bundles[len(bundles)-1]

	// Compute file path
	filePath := filepath.Join(s.plcCacheDir, fmt.Sprintf("%06d.jsonl.zst", lastBundle.BundleNumber))

	operations, err := s.loadBundleOperations(filePath)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to load bundle: %v", err), http.StatusInternalServerError)
		return
	}

	// Find latest operation for this DID
	var latestOp *plc.PLCOperation
	for i := len(operations) - 1; i >= 0; i-- {
		if operations[i].DID == did {
			latestOp = &operations[i]
			break
		}
	}

	if latestOp == nil {
		http.Error(w, "DID operation not found", http.StatusNotFound)
		return
	}

	respondJSON(w, latestOp)
}

func (s *Server) handleGetDIDHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	did := vars["did"]

	bundles, err := s.db.GetBundlesForDID(ctx, did)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if len(bundles) == 0 {
		http.Error(w, "DID not found in bundles", http.StatusNotFound)
		return
	}

	var allOperations []plc.DIDHistoryEntry
	var currentOp *plc.PLCOperation

	for _, bundle := range bundles {
		// Compute file path
		filePath := filepath.Join(s.plcCacheDir, fmt.Sprintf("%06d.jsonl.zst", bundle.BundleNumber))

		operations, err := s.loadBundleOperations(filePath)
		if err != nil {
			log.Error("Warning: failed to load bundle: %v", err)
			continue
		}

		for _, op := range operations {
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

	history := plc.DIDHistory{
		DID:        did,
		Current:    currentOp,
		Operations: allOperations,
	}

	respondJSON(w, history)
}

func (s *Server) handleGetPLCBundle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)

	bundleNumber, err := strconv.Atoi(vars["number"])
	if err != nil {
		http.Error(w, "invalid bundle number", http.StatusBadRequest)
		return
	}

	bundle, err := s.db.GetBundleByNumber(ctx, bundleNumber)
	if err != nil {
		http.Error(w, "bundle not found", http.StatusNotFound)
		return
	}

	response := map[string]interface{}{
		"plc_bundle_number": bundle.BundleNumber,
		"start_time":        bundle.StartTime,
		"end_time":          bundle.EndTime,
		"operation_count":   1000,
		"did_count":         len(bundle.DIDs),
		"hash":              bundle.Hash,           // Uncompressed (verifiable)
		"compressed_hash":   bundle.CompressedHash, // File integrity
		"compressed_size":   bundle.CompressedSize,
		"prev_bundle_hash":  bundle.PrevBundleHash,
		"created_at":        bundle.CreatedAt,
	}

	respondJSON(w, response)
}

func (s *Server) handleGetPLCBundleDIDs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)

	bundleNumber, err := strconv.Atoi(vars["number"])
	if err != nil {
		http.Error(w, "invalid bundle number", http.StatusBadRequest)
		return
	}

	bundle, err := s.db.GetBundleByNumber(ctx, bundleNumber)
	if err != nil {
		http.Error(w, "bundle not found", http.StatusNotFound)
		return
	}

	respondJSON(w, map[string]interface{}{
		"plc_bundle_number": bundle.BundleNumber,
		"did_count":         len(bundle.DIDs),
		"dids":              bundle.DIDs,
	})
}

func (s *Server) handleGetMempoolStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	count, err := s.db.GetMempoolCount(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	respondJSON(w, map[string]interface{}{
		"operation_count":   count,
		"can_create_bundle": count >= 1000,
	})
}

// Helper to load bundle operations - UPDATED FOR JSONL FORMAT
func (s *Server) loadBundleOperations(path string) ([]plc.PLCOperation, error) {
	decoder, err := zstd.NewReader(nil)
	if err != nil {
		return nil, err
	}
	defer decoder.Close()

	compressedData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	decompressed, err := decoder.DecodeAll(compressedData, nil)
	if err != nil {
		return nil, err
	}

	// Parse JSONL (newline-delimited JSON)
	var operations []plc.PLCOperation
	scanner := bufio.NewScanner(bytes.NewReader(decompressed))

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()

		// Skip empty lines
		if len(line) == 0 {
			continue
		}

		var op plc.PLCOperation
		if err := json.Unmarshal(line, &op); err != nil {
			return nil, fmt.Errorf("failed to parse operation on line %d: %w", lineNum, err)
		}

		operations = append(operations, op)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading JSONL: %w", err)
	}

	return operations, nil
}

func (s *Server) handleGetPLCMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	limit := 10
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil {
			limit = parsed
		}
	}

	metrics, err := s.db.GetPLCMetrics(ctx, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	respondJSON(w, metrics)
}

func (s *Server) handleGetPLCBundles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil {
			limit = parsed
		}
	}

	bundles, err := s.db.GetBundles(ctx, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := make([]map[string]interface{}, len(bundles))
	for i, bundle := range bundles {
		response[i] = map[string]interface{}{
			"plc_bundle_number": bundle.BundleNumber,
			"start_time":        bundle.StartTime,
			"end_time":          bundle.EndTime,
			"operation_count":   1000,
			"did_count":         len(bundle.DIDs),
			"hash":              bundle.Hash,
			"compressed_hash":   bundle.CompressedHash,
			"compressed_size":   bundle.CompressedSize,
			"prev_bundle_hash":  bundle.PrevBundleHash,
		}
	}

	respondJSON(w, response)
}

func (s *Server) handleGetPLCBundleStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	count, size, err := s.db.GetBundleStats(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	respondJSON(w, map[string]interface{}{
		"plc_bundle_count": count,
		"total_size":       size,
		"total_size_mb":    float64(size) / 1024 / 1024,
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) handleVerifyPLCBundle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	bundleNumberStr := vars["bundleNumber"]

	bundleNumber, err := strconv.Atoi(bundleNumberStr)
	if err != nil {
		http.Error(w, "Invalid bundle number", http.StatusBadRequest)
		return
	}

	// Get bundle from DB
	bundle, err := s.db.GetBundleByNumber(ctx, bundleNumber)
	if err != nil {
		http.Error(w, "Bundle not found", http.StatusNotFound)
		return
	}

	// Get previous bundle for 'after' timestamp
	prevBundle, err := s.db.GetBundleByNumber(ctx, bundleNumber-1)
	if err != nil && bundleNumber > 1 {
		http.Error(w, "Failed to get previous bundle", http.StatusInternalServerError)
		return
	}

	var after string
	if prevBundle != nil {
		after = prevBundle.EndTime.Format("2006-01-02T15:04:05.000Z")
	}

	// Fetch from PLC directory
	remoteOps, err := s.plcClient.Export(ctx, plc.ExportOptions{
		Count: 1000,
		After: after,
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch from PLC directory: %v", err), http.StatusInternalServerError)
		return
	}

	// Compute remote hash (uncompressed JSONL)
	remoteHash, err := computeRemoteOperationsHash(remoteOps)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to compute remote hash: %v", err), http.StatusInternalServerError)
		return
	}

	// Compare hashes (use uncompressed hash)
	verified := bundle.Hash == remoteHash

	respondJSON(w, map[string]interface{}{
		"bundle_number": bundleNumber,
		"verified":      verified,
		"local_hash":    bundle.Hash,
		"remote_hash":   remoteHash,
	})
}

func (s *Server) handleVerifyChain(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get last bundle number
	lastBundle, err := s.db.GetLastBundleNumber(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if lastBundle == 0 {
		respondJSON(w, map[string]interface{}{
			"status":  "empty",
			"message": "No bundles to verify",
		})
		return
	}

	// Verify chain
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

		// Verify chain link
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

	response := map[string]interface{}{
		"chain_length": lastBundle,
		"valid":        valid,
	}

	if !valid {
		response["broken_at"] = brokenAt
		response["error"] = errorMsg
	}

	respondJSON(w, response)
}

func (s *Server) handleGetChainInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	lastBundle, err := s.db.GetLastBundleNumber(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if lastBundle == 0 {
		respondJSON(w, map[string]interface{}{
			"chain_length": 0,
			"status":       "empty",
		})
		return
	}

	firstBundle, _ := s.db.GetBundleByNumber(ctx, 1)
	lastBundleData, _ := s.db.GetBundleByNumber(ctx, lastBundle)

	count, size, _ := s.db.GetBundleStats(ctx)

	respondJSON(w, map[string]interface{}{
		"chain_length":     lastBundle,
		"total_bundles":    count,
		"total_size_mb":    float64(size) / 1024 / 1024,
		"chain_start_time": firstBundle.StartTime,
		"chain_end_time":   lastBundleData.EndTime,
		"chain_head_hash":  lastBundleData.Hash,
		"first_prev_hash":  firstBundle.PrevBundleHash, // Should be empty
		"last_prev_hash":   lastBundleData.PrevBundleHash,
	})
}

// computeRemoteOperationsHash - matching format
func computeRemoteOperationsHash(ops []plc.PLCOperation) (string, error) {
	var jsonlData []byte
	for i, op := range ops {
		if len(op.RawJSON) > 0 {
			jsonlData = append(jsonlData, op.RawJSON...)
		} else {
			return "", fmt.Errorf("operation %d missing raw JSON data", i)
		}

		// Add newline ONLY between operations
		if i < len(ops)-1 {
			jsonlData = append(jsonlData, '\n')
		}
	}

	hash := sha256.Sum256(jsonlData)
	return hex.EncodeToString(hash[:]), nil
}

func respondJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// Helper function
func statusToString(status int) string {
	switch status {
	case storage.PDSStatusOnline:
		return "online"
	case storage.PDSStatusOffline:
		return "offline"
	default:
		return "unknown"
	}
}
