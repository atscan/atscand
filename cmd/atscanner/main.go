package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/atscan/atscanner/internal/api"
	"github.com/atscan/atscanner/internal/config"
	"github.com/atscan/atscanner/internal/pds"
	"github.com/atscan/atscanner/internal/plc"
	"github.com/atscan/atscanner/internal/storage"
	"github.com/atscan/atscanner/internal/worker"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize database
	db, err := storage.NewSQLiteDB(cfg.Database.Path)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Run migrations
	if err := db.Migrate(); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize workers
	plcScanner := plc.NewScanner(db, cfg.PLC)
	pdsScanner := pds.NewScanner(db, cfg.PDS)

	scheduler := worker.NewScheduler()

	// Schedule PLC directory scan
	scheduler.AddJob("plc_scan", cfg.PLC.ScanInterval, func() {
		if err := plcScanner.Scan(ctx); err != nil {
			log.Printf("PLC scan error: %v", err)
		}
	})

	// Schedule PDS availability checks
	scheduler.AddJob("pds_scan", cfg.PDS.ScanInterval, func() {
		if err := pdsScanner.ScanAll(ctx); err != nil {
			log.Printf("PDS scan error: %v", err)
		}
	})

	// Start API server
	apiServer := api.NewServer(db, cfg.API)
	go func() {
		if err := apiServer.Start(); err != nil {
			log.Fatalf("API server error: %v", err)
		}
	}()

	// Start scheduler
	scheduler.Start(ctx)

	// Wait for interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down gracefully...")
	cancel()
	apiServer.Shutdown(context.Background())
	time.Sleep(2 * time.Second)
}
