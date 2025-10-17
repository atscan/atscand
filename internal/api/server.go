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
	api.HandleFunc("/pds/{endpoint}", s.handleGetPDS).Methods("GET")
	api.HandleFunc("/pds/stats", s.handleGetPDSStats).Methods("GET")

	// Metrics endpoints
	api.HandleFunc("/metrics/plc", s.handleGetPLCMetrics).Methods("GET")

	// Bundle endpoints - NEW
	api.HandleFunc("/bundles", s.handleGetBundles).Methods("GET")
	api.HandleFunc("/bundles/stats", s.handleGetBundleStats).Methods("GET")

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
