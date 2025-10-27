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
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

type Server struct {
	router        *mux.Router
	server        *http.Server
	db            storage.Database
	plcClient     *plc.Client
	plcBundleDir  string
	bundleManager *plc.BundleManager
	plcIndexDIDs  bool
}

func NewServer(db storage.Database, apiCfg config.APIConfig, plcCfg config.PLCConfig) *Server {
	bundleManager, _ := plc.NewBundleManager(plcCfg.BundleDir, plcCfg.UseCache, db, plcCfg.IndexDIDs)

	s := &Server{
		router:        mux.NewRouter(),
		db:            db,
		plcClient:     plc.NewClient(plcCfg.DirectoryURL),
		plcBundleDir:  plcCfg.BundleDir,
		bundleManager: bundleManager,
		plcIndexDIDs:  plcCfg.IndexDIDs,
	}

	s.setupRoutes()

	// Add CORS middleware
	corsHandler := handlers.CORS(
		handlers.AllowedOrigins([]string{"*"}),
		handlers.AllowedMethods([]string{"GET", "POST", "OPTIONS"}),
		handlers.AllowedHeaders([]string{"Content-Type", "X-Requested-With"}),
	)

	s.server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", apiCfg.Host, apiCfg.Port),
		Handler:      corsHandler(s.router),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	return s
}

func (s *Server) setupRoutes() {
	api := s.router.PathPrefix("/api/v1").Subrouter()

	// Generic endpoints (keep as-is)
	api.HandleFunc("/endpoints", s.handleGetEndpoints).Methods("GET")
	api.HandleFunc("/endpoints/stats", s.handleGetEndpointStats).Methods("GET")
	api.HandleFunc("/endpoints/random", s.handleGetRandomEndpoint).Methods("GET")

	//PDS-specific endpoints (virtual, created via JOINs)
	api.HandleFunc("/pds", s.handleGetPDSList).Methods("GET")
	api.HandleFunc("/pds/stats", s.handleGetPDSStats).Methods("GET")
	api.HandleFunc("/pds/countries", s.handleGetCountryLeaderboard).Methods("GET")
	api.HandleFunc("/pds/versions", s.handleGetVersionStats).Methods("GET")
	api.HandleFunc("/pds/duplicates", s.handleGetDuplicateEndpoints).Methods("GET")
	api.HandleFunc("/pds/{endpoint}", s.handleGetPDSDetail).Methods("GET")

	// PDS repos
	api.HandleFunc("/pds/{endpoint}/repos", s.handleGetPDSRepos).Methods("GET")
	api.HandleFunc("/pds/{endpoint}/repos/stats", s.handleGetPDSRepoStats).Methods("GET")
	api.HandleFunc("/pds/repos/{did}", s.handleGetDIDRepos).Methods("GET")

	// Global DID routes
	api.HandleFunc("/did/{did}", s.handleGetGlobalDID).Methods("GET")
	api.HandleFunc("/handle/{handle}", s.handleGetDIDByHandle).Methods("GET") // NEW

	// PLC Bundle routes
	api.HandleFunc("/plc/bundles", s.handleGetPLCBundles).Methods("GET")
	api.HandleFunc("/plc/bundles/stats", s.handleGetPLCBundleStats).Methods("GET")
	api.HandleFunc("/plc/bundles/chain", s.handleGetChainInfo).Methods("GET")
	api.HandleFunc("/plc/bundles/verify-chain", s.handleVerifyChain).Methods("POST")
	api.HandleFunc("/plc/bundles/{number}", s.handleGetPLCBundle).Methods("GET")
	api.HandleFunc("/plc/bundles/{number}/dids", s.handleGetPLCBundleDIDs).Methods("GET")
	api.HandleFunc("/plc/bundles/{number}/download", s.handleDownloadPLCBundle).Methods("GET")
	api.HandleFunc("/plc/bundles/{bundleNumber}/verify", s.handleVerifyPLCBundle).Methods("POST")

	// PLC history/metrics
	api.HandleFunc("/plc/history", s.handleGetPLCHistory).Methods("GET")

	// PLC Export endpoint (simulates PLC directory)
	api.HandleFunc("/plc/export", s.handlePLCExport).Methods("GET")

	// DID routes
	api.HandleFunc("/plc/did/{did}", s.handleGetDID).Methods("GET")
	api.HandleFunc("/plc/did/{did}/history", s.handleGetDIDHistory).Methods("GET")
	api.HandleFunc("/plc/dids/stats", s.handleGetDIDStats).Methods("GET")

	// Mempool routes
	api.HandleFunc("/mempool/stats", s.handleGetMempoolStats).Methods("GET")

	// Metrics routes
	api.HandleFunc("/metrics/plc", s.handleGetPLCMetrics).Methods("GET")

	// Debug Endpoints
	api.HandleFunc("/debug/db/sizes", s.handleGetDBSizes).Methods("GET")
	api.HandleFunc("/jobs", s.handleGetJobStatus).Methods("GET")

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
