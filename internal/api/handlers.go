package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/atscan/atscanner/internal/storage"
	"github.com/gorilla/mux"
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

func (s *Server) handleGetDIDList(w http.ResponseWriter, r *http.Request) {
	// Implementation similar to PDS list
}

func (s *Server) handleGetDID(w http.ResponseWriter, r *http.Request) {
	// Implementation for getting single DID
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
