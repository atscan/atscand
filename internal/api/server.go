package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/atscan/atscanner/internal/config"
	"github.com/atscan/atscanner/internal/log"
	"github.com/atscan/atscanner/internal/plc"
	"github.com/atscan/atscanner/internal/storage"
	"github.com/gorilla/mux"
)

type Server struct {
	router       *mux.Router
	server       *http.Server
	db           storage.Database
	plcClient    *plc.Client
	plcBundleDir string // NEW: Store cache dir
}

func NewServer(db storage.Database, apiCfg config.APIConfig, plcCfg config.PLCConfig) *Server {
	s := &Server{
		router:       mux.NewRouter(),
		db:           db,
		plcClient:    plc.NewClient(plcCfg.DirectoryURL),
		plcBundleDir: plcCfg.BundleDir, // NEW
	}

	s.setupRoutes()

	s.server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", apiCfg.Host, apiCfg.Port),
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

	// PLC Bundle endpoints
	api.HandleFunc("/plc/bundles", s.handleGetPLCBundles).Methods("GET")
	api.HandleFunc("/plc/bundles/stats", s.handleGetPLCBundleStats).Methods("GET")
	api.HandleFunc("/plc/bundles/chain", s.handleGetChainInfo).Methods("GET")
	api.HandleFunc("/plc/bundles/verify-chain", s.handleVerifyChain).Methods("POST")
	api.HandleFunc("/plc/bundles/{number}/dids", s.handleGetPLCBundleDIDs).Methods("GET")
	api.HandleFunc("/plc/bundles/{bundleNumber}/verify", s.handleVerifyPLCBundle).Methods("POST")
	api.HandleFunc("/plc/bundles/{number}", s.handleGetPLCBundle).Methods("GET")
	api.HandleFunc("/plc/export", s.handlePLCExport).Methods("GET")

	// PLC/DID endpoints
	api.HandleFunc("/plc/did/{did}", s.handleGetDID).Methods("GET")
	api.HandleFunc("/plc/did/{did}/history", s.handleGetDIDHistory).Methods("GET")

	// Mempool endpoint - NEW
	api.HandleFunc("/mempool/stats", s.handleGetMempoolStats).Methods("GET")

	// Chain verification - NEW

	// Health check
	s.router.HandleFunc("/health", s.handleHealth).Methods("GET")
}
func (s *Server) Start() error {
	log.Info("API server listening on %s", s.server.Addr)
	return s.server.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}
