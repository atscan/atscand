package pds

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/acarl005/stripansi"
	"github.com/atscan/atscanner/internal/config"
	"github.com/atscan/atscanner/internal/ipinfo"
	"github.com/atscan/atscanner/internal/log"
	"github.com/atscan/atscanner/internal/storage"
)

type Scanner struct {
	client       *Client
	db           storage.Database
	config       config.PDSConfig
	ipInfoClient *ipinfo.Client
}

func NewScanner(db storage.Database, cfg config.PDSConfig) *Scanner {
	return &Scanner{
		client:       NewClient(cfg.Timeout),
		db:           db,
		config:       cfg,
		ipInfoClient: ipinfo.NewClient(),
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

	// 2. ADD THIS BLOCK TO SHUFFLE THE LIST
	if len(servers) > 0 {
		// Create a new random source to avoid using the global one
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		// Shuffle the servers slice in place
		r.Shuffle(len(servers), func(i, j int) {
			servers[i], servers[j] = servers[j], servers[i]
		})
		log.Info("Randomized scan order for %d PDS servers...", len(servers))
	} else {
		log.Info("Scanning 0 PDS servers...")
		return nil // No need to continue if there are no servers
	}

	// Worker pool
	jobs := make(chan *storage.Endpoint, len(servers))
	var wg sync.WaitGroup

	for i := 0; i < s.config.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.worker(ctx, jobs)
		}()
	}

	// Send jobs
	for _, server := range servers {
		jobs <- server
	}
	close(jobs)

	// Wait for completion
	wg.Wait()

	log.Info("PDS scan completed in %v", time.Since(startTime))

	return nil
}

func (s *Scanner) worker(ctx context.Context, jobs <-chan *storage.Endpoint) {
	for server := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
			s.scanAndSaveEndpoint(ctx, server)
		}
	}
}

func (s *Scanner) scanAndSaveEndpoint(ctx context.Context, ep *storage.Endpoint) {
	// STEP 1: Resolve IP (before any network call)
	ip, err := ipinfo.ExtractIPFromEndpoint(ep.Endpoint)
	if err != nil {
		// Mark as offline due to DNS failure
		s.saveScanResult(ctx, ep.ID, &ScanResult{
			Status:       storage.EndpointStatusOffline,
			ErrorMessage: fmt.Sprintf("DNS resolution failed: %v", err),
		})
		return
	}

	// Update IP immediately
	s.db.UpdateEndpointIP(ctx, ep.ID, ip, time.Now().UTC())

	// STEP 2: Health check
	available, responseTime, version, err := s.client.CheckHealth(ctx, ep.Endpoint) // CHANGED: receive version
	if err != nil || !available {
		errMsg := "health check failed"
		if err != nil {
			errMsg = err.Error()
		}
		s.saveScanResult(ctx, ep.ID, &ScanResult{
			Status:       storage.EndpointStatusOffline,
			ResponseTime: responseTime,
			ErrorMessage: errMsg,
		})
		return
	}

	// STEP 3: Fetch PDS-specific data
	desc, err := s.client.DescribeServer(ctx, ep.Endpoint)
	if err != nil {
		log.Verbose("Warning: failed to describe server %s: %v", stripansi.Strip(ep.Endpoint), err)
	}

	dids, err := s.client.ListRepos(ctx, ep.Endpoint)
	if err != nil {
		log.Verbose("Warning: failed to list repos for %s: %v", ep.Endpoint, err)
		dids = []string{}
	}

	// STEP 4: SAVE IMMEDIATELY
	s.saveScanResult(ctx, ep.ID, &ScanResult{
		Status:       storage.EndpointStatusOnline,
		ResponseTime: responseTime,
		Description:  desc,
		DIDs:         dids,
		Version:      version, // CHANGED: Pass version
	})

	// STEP 5: Fetch IP info if needed (async, with backoff)
	go s.updateIPInfoIfNeeded(ctx, ip)
}

func (s *Scanner) saveScanResult(ctx context.Context, endpointID int64, result *ScanResult) {
	// Build scan_data with PDS-specific info in Metadata
	scanData := &storage.EndpointScanData{
		DIDCount: len(result.DIDs),
		Metadata: make(map[string]interface{}),
	}

	var userCount int64 // NEW: Declare user count

	// Add PDS-specific metadata
	if result.Status == storage.EndpointStatusOnline {
		userCount = int64(len(result.DIDs))         // NEW: Get user count
		scanData.Metadata["user_count"] = userCount // Keep in JSON for completeness
		if result.Description != nil {
			scanData.Metadata["server_info"] = result.Description
		}
	} else {
		// Include error message for offline status
		if result.ErrorMessage != "" {
			scanData.Metadata["error"] = result.ErrorMessage
		}
	}

	// Save scan record
	scan := &storage.EndpointScan{
		EndpointID:   endpointID,
		Status:       result.Status,
		ResponseTime: result.ResponseTime.Seconds() * 1000, // Convert to ms
		UserCount:    userCount,
		Version:      result.Version, // NEW: Set the version field
		ScanData:     scanData,
		ScannedAt:    time.Now().UTC(),
	}

	if err := s.db.SaveEndpointScan(ctx, scan); err != nil {
		log.Error("Failed to save scan for endpoint %d: %v", endpointID, err)
	}

	// Update endpoint status
	update := &storage.EndpointUpdate{
		Status:       result.Status,
		LastChecked:  time.Now().UTC(),
		ResponseTime: result.ResponseTime.Seconds() * 1000,
	}

	if err := s.db.UpdateEndpointStatus(ctx, endpointID, update); err != nil {
		log.Error("Failed to update endpoint status for %d: %v", endpointID, err)
	}
}

func (s *Scanner) updateIPInfoIfNeeded(ctx context.Context, ip string) {
	// Check if IP info client is in backoff
	if s.ipInfoClient.IsInBackoff() {
		return
	}

	// Check if we need to update IP info
	exists, needsUpdate, err := s.db.ShouldUpdateIPInfo(ctx, ip)
	if err != nil {
		log.Verbose("Failed to check IP info status: %v", err)
		return
	}

	if exists && !needsUpdate {
		return // IP info is fresh
	}

	// Fetch IP info from ipapi.is
	log.Verbose("Fetching IP info for %s", ip)
	ipInfo, err := s.ipInfoClient.GetIPInfo(ctx, ip)
	if err != nil {
		// Log only once when backoff starts
		if s.ipInfoClient.IsInBackoff() {
			log.Info("⚠ IP info API unavailable, pausing requests for 5 minutes")
		} else {
			log.Verbose("Failed to fetch IP info for %s: %v", ip, err)
		}
		return
	}

	// Update database
	if err := s.db.UpsertIPInfo(ctx, ip, ipInfo); err != nil {
		log.Error("Failed to update IP info for %s: %v", ip, err)
	} else {
		log.Verbose("✓ Updated IP info for %s", ip)
	}
}
