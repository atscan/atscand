package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

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

	respondJSON(w, servers)
}

func (s *Server) handleGetPDS(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	endpoint := vars["endpoint"]

	pds, err := s.db.GetPDS(ctx, endpoint)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	respondJSON(w, pds)
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

	// Get all bundles and search for DID
	bundles, err := s.db.GetAllBundles(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Find bundles containing this DID
	var relevantBundles []*storage.PLCBundle
	for _, bundle := range bundles {
		for _, bundleDID := range bundle.DIDs {
			if bundleDID == did {
				relevantBundles = append(relevantBundles, bundle)
				break
			}
		}
	}

	if len(relevantBundles) == 0 {
		http.Error(w, "DID not found in bundles", http.StatusNotFound)
		return
	}

	// Load the last bundle and find latest operation
	lastBundle := relevantBundles[len(relevantBundles)-1]

	operations, err := s.loadBundleOperations(lastBundle.FilePath)
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

	// Get all bundles
	bundles, err := s.db.GetAllBundles(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Find bundles containing this DID
	var relevantBundles []*storage.PLCBundle
	for _, bundle := range bundles {
		for _, bundleDID := range bundle.DIDs {
			if bundleDID == did {
				relevantBundles = append(relevantBundles, bundle)
				break
			}
		}
	}

	if len(relevantBundles) == 0 {
		http.Error(w, "DID not found in bundles", http.StatusNotFound)
		return
	}

	var allOperations []plc.DIDHistoryEntry
	var currentOp *plc.PLCOperation

	// Load relevant bundles
	for _, bundle := range relevantBundles {
		operations, err := s.loadBundleOperations(bundle.FilePath)
		if err != nil {
			log.Printf("Warning: failed to load bundle: %v", err)
			continue
		}

		for _, op := range operations {
			if op.DID == did {
				entry := plc.DIDHistoryEntry{
					Operation: op,
					Bundle:    filepath.Base(bundle.FilePath),
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

func (s *Server) handleGetBundleDIDs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)

	bundleID, err := strconv.ParseInt(vars["id"], 10, 64)
	if err != nil {
		http.Error(w, "invalid bundle ID", http.StatusBadRequest)
		return
	}

	// Get all bundles and find the one we want
	bundles, err := s.db.GetAllBundles(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	for _, bundle := range bundles {
		if bundle.ID == bundleID {
			respondJSON(w, map[string]interface{}{
				"bundle_id": bundleID,
				"did_count": len(bundle.DIDs),
				"dids":      bundle.DIDs,
			})
			return
		}
	}

	http.Error(w, "bundle not found", http.StatusNotFound)
}

// Helper to load bundle operations
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

	var operations []plc.PLCOperation
	if err := json.Unmarshal(decompressed, &operations); err != nil {
		return nil, err
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

func (s *Server) handleGetBundles(w http.ResponseWriter, r *http.Request) {
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

	respondJSON(w, bundles)
}

func (s *Server) handleGetBundleStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	count, size, err := s.db.GetBundleStats(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	respondJSON(w, map[string]interface{}{
		"bundle_count":  count,
		"total_size":    size,
		"total_size_mb": float64(size) / 1024 / 1024,
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, map[string]string{"status": "ok"})
}

func respondJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}
