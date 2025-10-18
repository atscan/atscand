package api

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/atscan/atscanner/internal/config"
	"github.com/atscan/atscanner/internal/storage"
	"github.com/gorilla/mux"
)

type Server struct {
	router *mux.Router
	server *http.Server
	db     storage.Database
}

func NewServer(db storage.Database, cfg config.APIConfig) *Server {
	s := &Server{
		router: mux.NewRouter(),
		db:     db,
	}

	s.setupRoutes()

	s.server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Handler:      s.router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	return s
}

func (s *Server) setupRoutes() {
	api := s.router.PathPrefix("/api/v1").Subrouter()

	// PDS endpoints
	api.HandleFunc("/pds", s.handleGetPDSList).Methods("GET")
	api.HandleFunc("/pds/stats", s.handleGetPDSStats).Methods("GET")
	api.HandleFunc("/pds/{endpoint}", s.handleGetPDS).Methods("GET")

	// Metrics endpoints
	api.HandleFunc("/metrics/plc", s.handleGetPLCMetrics).Methods("GET")

	// Bundle endpoints - UPDATED to use bundle number
	api.HandleFunc("/bundles", s.handleGetBundles).Methods("GET")
	api.HandleFunc("/bundles/stats", s.handleGetBundleStats).Methods("GET")
	api.HandleFunc("/bundles/{number}/dids", s.handleGetBundleDIDs).Methods("GET") // Changed
	api.HandleFunc("/bundles/{number}", s.handleGetBundle).Methods("GET")          // NEW

	// PLC/DID endpoints
	api.HandleFunc("/plc/{did}", s.handleGetDID).Methods("GET")
	api.HandleFunc("/plc/{did}/history", s.handleGetDIDHistory).Methods("GET")

	// Mempool endpoint - NEW
	api.HandleFunc("/mempool/stats", s.handleGetMempoolStats).Methods("GET")

	// Health check
	s.router.HandleFunc("/health", s.handleHealth).Methods("GET")
}
func (s *Server) Start() error {
	log.Printf("API server listening on %s", s.server.Addr)
	return s.server.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}
