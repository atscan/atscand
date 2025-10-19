package main

import (
	"context"
	"flag"
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

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	verbose := flag.Bool("verbose", false, "enable verbose logging")
	flag.Parse()

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatal("Failed to load config: %v", err)
	}

	// Override verbose setting if flag is provided
	if *verbose {
		cfg.API.Verbose = true
	}

	// Initialize logger
	log.Init(cfg.API.Verbose)

	// Initialize database
	db, err := storage.NewSQLiteDB(cfg.Database.Path)
	if err != nil {
		log.Fatal("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Run migrations
	if err := db.Migrate(); err != nil {
		log.Fatal("Failed to run migrations: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize workers
	plcScanner := plc.NewScanner(db, cfg.PLC)
	defer plcScanner.Close() // Close scanner to cleanup cache

	pdsScanner := pds.NewScanner(db, cfg.PDS)

	scheduler := worker.NewScheduler()

	// Schedule PLC directory scan
	scheduler.AddJob("plc_scan", cfg.PLC.ScanInterval, func() {
		if err := plcScanner.Scan(ctx); err != nil {
			log.Error("PLC scan error: %v", err)
		}
	})

	// Schedule PDS availability checks
	scheduler.AddJob("pds_scan", cfg.PDS.ScanInterval, func() {
		if err := pdsScanner.ScanAll(ctx); err != nil {
			log.Error("PDS scan error: %v", err)
		}
	})

	// Start API server
	apiServer := api.NewServer(db, cfg.API, cfg.PLC)
	go func() {
		if err := apiServer.Start(); err != nil {
			log.Fatal("API server error: %v", err)
		}
	}()

	// Start scheduler
	scheduler.Start(ctx)

	// Wait for interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Info("Shutting down gracefully...")
	cancel()
	apiServer.Shutdown(context.Background())
	time.Sleep(2 * time.Second)
}
