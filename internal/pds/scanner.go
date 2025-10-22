package pds

import (
	"context"
	"sync"
	"time"

	"github.com/acarl005/stripansi"
	"github.com/atscan/atscanner/internal/config"
	"github.com/atscan/atscanner/internal/log"
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
	log.Info("Starting PDS availability scan...")

	// Get only PDS endpoints
	servers, err := s.db.GetEndpoints(ctx, &storage.EndpointFilter{
		Type: "pds",
	})
	if err != nil {
		return err
	}

	log.Info("Scanning %d PDS servers...", len(servers))

	// Worker pool
	jobs := make(chan *storage.Endpoint, len(servers))
	results := make(chan *PDSStatus, len(servers))

	var wg sync.WaitGroup
	for i := 0; i < s.config.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.worker(ctx, jobs, results)
		}()
	}

	go func() {
		for _, server := range servers {
			jobs <- server
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	// Process results
	successCount := 0
	failureCount := 0
	totalUsers := int64(0)

	for status := range results {
		// Determine status code
		statusCode := storage.PDSStatusOffline
		if status.Available {
			statusCode = storage.PDSStatusOnline
		}

		// Build scan data
		scanData := &storage.EndpointScanData{
			ServerInfo: status.Description,
			DIDs:       status.DIDs,
			DIDCount:   len(status.DIDs),
		}

		// Update using Endpoint ID
		if err := s.db.UpdateEndpointStatus(ctx, status.EndpointID, &storage.EndpointUpdate{
			Status:       statusCode,
			LastChecked:  status.LastChecked,
			ResponseTime: status.ResponseTime.Seconds() * 1000, // Convert to ms
			ScanData:     scanData,
		}); err != nil {
			log.Error("Error updating endpoint ID %d: %v", status.EndpointID, err)
		}

		if status.Available {
			successCount++
			totalUsers += int64(len(status.DIDs))
		} else {
			failureCount++
		}
	}

	log.Info("PDS scan completed: %d available, %d unavailable, %d total users in %v",
		successCount, failureCount, totalUsers, time.Since(startTime))

	return nil
}

func (s *Scanner) worker(ctx context.Context, jobs <-chan *storage.Endpoint, results chan<- *PDSStatus) {
	for server := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
			status := s.scanPDS(ctx, server.ID, server.Endpoint)
			results <- status
		}
	}
}

func (s *Scanner) scanPDS(ctx context.Context, endpointID int64, endpoint string) *PDSStatus {
	status := &PDSStatus{
		EndpointID:  endpointID, // Store Endpoint ID
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
		log.Verbose("Warning: failed to describe server %s: %v", stripansi.Strip(endpoint), err)
	} else {
		status.Description = desc
	}

	// Optionally list repos (DIDs) - commented out by default for performance
	/*dids, err := s.client.ListRepos(ctx, endpoint)
	if err != nil {
		log.Verbose("Warning: failed to list repos for %s: %v", endpoint, err)
		status.DIDs = []string{}
	} else {
		status.DIDs = dids
		log.Verbose("  → Found %d users on %s", len(dids), endpoint)
	}*/

	return status
}
