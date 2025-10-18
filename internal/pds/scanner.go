package pds

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/atscan/atscanner/internal/config"
	"github.com/atscan/atscanner/internal/storage"
)

type Scanner struct {
	client *Client
	db     storage.Database
	config config.PDSConfig
}

func NewScanner(db storage.Database, cfg config.PDSConfig) *Scanner {
	return &Scanner{
		client: NewClient(cfg.Timeout),
		db:     db,
		config: cfg,
	}
}

func (s *Scanner) ScanAll(ctx context.Context) error {
	startTime := time.Now()
	log.Println("Starting PDS availability scan...")

	// Get all PDS servers to check
	servers, err := s.db.GetPDSServers(ctx, nil)
	if err != nil {
		return err
	}

	log.Printf("Scanning %d PDS servers...", len(servers))

	// Worker pool
	jobs := make(chan *storage.PDS, len(servers))
	results := make(chan *PDSStatus, len(servers))

	var wg sync.WaitGroup
	for i := 0; i < s.config.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.worker(ctx, jobs, results)
		}()
	}

	// Send jobs
	go func() {
		for _, server := range servers {
			jobs <- server
		}
		close(jobs)
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(results)
	}()

	// Process results
	successCount := 0
	failureCount := 0
	totalUsers := int64(0)

	for status := range results {
		if err := s.db.UpdatePDSStatus(ctx, status.Endpoint, &storage.PDSUpdate{
			Status:       s.statusString(status.Available),
			LastChecked:  status.LastChecked,
			ResponseTime: status.ResponseTime.Milliseconds(),
			ErrorMessage: status.ErrorMessage,
			ServerInfo:   status.Description,
			DIDs:         status.DIDs, // NEW: Store DIDs
		}); err != nil {
			log.Printf("Error updating PDS %s: %v", status.Endpoint, err)
		}

		if status.Available {
			successCount++
			totalUsers += int64(len(status.DIDs))
		} else {
			failureCount++
		}
	}

	log.Printf("PDS scan completed: %d available, %d unavailable, %d total users in %v",
		successCount, failureCount, totalUsers, time.Since(startTime))

	return nil
}

func (s *Scanner) worker(ctx context.Context, jobs <-chan *storage.PDS, results chan<- *PDSStatus) {
	for server := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
			status := s.scanPDS(ctx, server.Endpoint)
			results <- status
		}
	}
}

func (s *Scanner) scanPDS(ctx context.Context, endpoint string) *PDSStatus {
	status := &PDSStatus{
		Endpoint:    endpoint,
		LastChecked: time.Now(),
	}

	// Health check
	available, responseTime, err := s.client.CheckHealth(ctx, endpoint)
	status.Available = available
	status.ResponseTime = responseTime

	if err != nil {
		status.ErrorMessage = err.Error()
		return status
	}

	if !available {
		status.ErrorMessage = "health check failed"
		return status
	}

	// Describe server
	desc, err := s.client.DescribeServer(ctx, endpoint)
	if err != nil {
		log.Printf("Warning: failed to describe server %s: %v", endpoint, err)
	} else {
		status.Description = desc
	}

	// List repos (DIDs) - NEW
	dids, err := s.client.ListRepos(ctx, endpoint)
	if err != nil {
		log.Printf("Warning: failed to list repos for %s: %v", endpoint, err)
		status.DIDs = []string{} // Empty if failed
	} else {
		status.DIDs = dids
		log.Printf("  → Found %d users on %s", len(dids), endpoint)
	}

	return status
}

func (s *Scanner) statusString(available bool) string {
	if available {
		return "online"
	}
	return "offline"
}
