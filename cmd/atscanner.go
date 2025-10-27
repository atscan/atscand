package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/atscan/atscanner/internal/api"
	"github.com/atscan/atscanner/internal/config"
	"github.com/atscan/atscanner/internal/log"
	"github.com/atscan/atscanner/internal/pds"
	"github.com/atscan/atscanner/internal/plc"
	"github.com/atscan/atscanner/internal/storage"
	"github.com/atscan/atscanner/internal/worker"
)

const VERSION = "1.0.0"

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	verbose := flag.Bool("verbose", false, "enable verbose logging")
	flag.Parse()

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Override verbose setting if flag is provided
	if *verbose {
		cfg.API.Verbose = true
	}

	// Initialize logger
	log.Init(cfg.API.Verbose)

	// Print banner
	log.Banner(VERSION)

	// Print configuration summary
	log.PrintConfig(map[string]string{
		"Database Type":     cfg.Database.Type,
		"Database Path":     cfg.Database.Path, // Will be auto-redacted
		"PLC Directory":     cfg.PLC.DirectoryURL,
		"PLC Scan Interval": cfg.PLC.ScanInterval.String(),
		"PLC Bundle Dir":    cfg.PLC.BundleDir,
		"PLC Cache":         fmt.Sprintf("%v", cfg.PLC.UseCache),
		"PLC Index DIDs":    fmt.Sprintf("%v", cfg.PLC.IndexDIDs),
		"PDS Scan Interval": cfg.PDS.ScanInterval.String(),
		"PDS Workers":       fmt.Sprintf("%d", cfg.PDS.Workers),
		"PDS Timeout":       cfg.PDS.Timeout.String(),
		"API Host":          cfg.API.Host,
		"API Port":          fmt.Sprintf("%d", cfg.API.Port),
		"Verbose Logging":   fmt.Sprintf("%v", cfg.API.Verbose),
	})

	// Initialize database using factory pattern
	db, err := storage.NewDatabase(cfg.Database.Type, cfg.Database.Path)
	if err != nil {
		log.Fatal("Failed to initialize database: %v", err)
	}
	defer func() {
		log.Info("Closing database connection...")
		db.Close()
	}()

	// Set scan retention from config
	if cfg.PDS.ScanRetention > 0 {
		db.SetScanRetention(cfg.PDS.ScanRetention)
		log.Verbose("Scan retention set to %d scans per endpoint", cfg.PDS.ScanRetention)
	}

	// Run migrations
	if err := db.Migrate(); err != nil {
		log.Fatal("Failed to run migrations: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize workers
	log.Info("Initializing scanners...")

	bundleManager, err := plc.NewBundleManager(cfg.PLC.BundleDir, cfg.PLC.DirectoryURL, db, cfg.PLC.IndexDIDs)
	if err != nil {
		log.Fatal("Failed to create bundle manager: %v", err)
	}
	defer bundleManager.Close()
	log.Verbose("✓ Bundle manager initialized (shared)")

	plcScanner := plc.NewScanner(db, cfg.PLC, bundleManager)
	defer plcScanner.Close()
	log.Verbose("✓ PLC scanner initialized")

	pdsScanner := pds.NewScanner(db, cfg.PDS)
	log.Verbose("✓ PDS scanner initialized")

	scheduler := worker.NewScheduler()

	// Schedule PLC directory scan
	scheduler.AddJob("plc_scan", cfg.PLC.ScanInterval, func() {
		if err := plcScanner.Scan(ctx); err != nil {
			log.Error("PLC scan error: %v", err)
		}
	})
	log.Verbose("✓ PLC scan job scheduled (interval: %s)", cfg.PLC.ScanInterval)

	// Schedule PDS availability checks
	scheduler.AddJob("pds_scan", cfg.PDS.ScanInterval, func() {
		if err := pdsScanner.ScanAll(ctx); err != nil {
			log.Error("PDS scan error: %v", err)
		}
	})
	log.Verbose("✓ PDS scan job scheduled (interval: %s)", cfg.PDS.ScanInterval)

	// Start API server
	log.Info("Starting API server on %s:%d...", cfg.API.Host, cfg.API.Port)
	apiServer := api.NewServer(db, cfg.API, cfg.PLC, bundleManager)
	go func() {
		if err := apiServer.Start(); err != nil {
			log.Fatal("API server error: %v", err)
		}
	}()

	// Give the API server a moment to start
	time.Sleep(100 * time.Millisecond)
	log.Info("✓ API server started successfully")
	log.Info("")
	log.Info("🚀 ATScanner is running!")
	log.Info("   API available at: http://%s:%d", cfg.API.Host, cfg.API.Port)
	log.Info("   Press Ctrl+C to stop")
	log.Info("")

	// Start scheduler
	scheduler.Start(ctx)

	// Wait for interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Info("")
	log.Info("Shutting down gracefully...")
	cancel()

	log.Info("Stopping API server...")
	apiServer.Shutdown(context.Background())

	log.Info("Waiting for active tasks to complete...")
	time.Sleep(2 * time.Second)

	log.Info("✓ Shutdown complete. Goodbye!")
}
