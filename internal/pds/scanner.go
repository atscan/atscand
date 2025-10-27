package pds

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/acarl005/stripansi"
	"github.com/atscan/atscanner/internal/config"
	"github.com/atscan/atscanner/internal/ipinfo"
	"github.com/atscan/atscanner/internal/log"
	"github.com/atscan/atscanner/internal/monitor"
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

	// Get only PDS endpoints that need checking
	servers, err := s.db.GetEndpoints(ctx, &storage.EndpointFilter{
		Type:            "pds",
		OnlyStale:       true,
		RecheckInterval: s.config.RecheckInterval,
	})
	if err != nil {
		return err
	}

	if len(servers) == 0 {
		log.Info("No endpoints need scanning at this time")
		monitor.GetTracker().UpdateProgress("pds_scan", 0, 0, "No endpoints need scanning")
		return nil
	}

	log.Info("Found %d endpoints that need scanning", len(servers))
	monitor.GetTracker().UpdateProgress("pds_scan", 0, len(servers), "Preparing to scan")

	// Shuffle servers
	if len(servers) > 0 {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		r.Shuffle(len(servers), func(i, j int) {
			servers[i], servers[j] = servers[j], servers[i]
		})
	}

	// Initialize workers in tracker
	monitor.GetTracker().InitWorkers("pds_scan", s.config.Workers)

	// Worker pool with progress tracking
	jobs := make(chan *workerJob, len(servers))
	var wg sync.WaitGroup
	var completed int32

	for i := 0; i < s.config.Workers; i++ {
		wg.Add(1)
		workerID := i + 1
		go func(id int) {
			defer wg.Done()
			s.workerWithProgress(ctx, id, jobs, &completed, len(servers))
		}(workerID)
	}

	// Send jobs
	for _, server := range servers {
		jobs <- &workerJob{endpoint: server}
	}
	close(jobs)

	// Wait for completion
	wg.Wait()

	log.Info("PDS scan completed in %v", time.Since(startTime))
	monitor.GetTracker().UpdateProgress("pds_scan", len(servers), len(servers), "Completed")

	return nil
}

type workerJob struct {
	endpoint *storage.Endpoint
}

func (s *Scanner) workerWithProgress(ctx context.Context, workerID int, jobs <-chan *workerJob, completed *int32, total int) {
	for job := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
			// Update worker status
			monitor.GetTracker().StartWorker("pds_scan", workerID, job.endpoint.Endpoint)

			// Scan endpoint
			s.scanAndSaveEndpoint(ctx, job.endpoint)

			// Update progress
			atomic.AddInt32(completed, 1)
			current := atomic.LoadInt32(completed)
			monitor.GetTracker().UpdateProgress("pds_scan", int(current), total,
				fmt.Sprintf("Scanned %d/%d endpoints", current, total))

			// Mark worker as idle
			monitor.GetTracker().CompleteWorker("pds_scan", workerID)
		}
	}
}

func (s *Scanner) scanAndSaveEndpoint(ctx context.Context, ep *storage.Endpoint) {
	// STEP 1: Resolve IPs (both IPv4 and IPv6)
	ips, err := ipinfo.ExtractIPsFromEndpoint(ep.Endpoint)
	if err != nil {
		// Mark as offline due to DNS failure
		s.saveScanResult(ctx, ep.ID, &ScanResult{
			Status:       storage.EndpointStatusOffline,
			ErrorMessage: fmt.Sprintf("DNS resolution failed: %v", err),
		})
		return
	}

	// Update IPs immediately
	s.db.UpdateEndpointIPs(ctx, ep.ID, ips.IPv4, ips.IPv6, time.Now().UTC())

	// STEP 1.5: Fetch IP info asynchronously for both IPs
	if ips.IPv4 != "" {
		go s.updateIPInfoIfNeeded(ctx, ips.IPv4)
	}
	if ips.IPv6 != "" {
		go s.updateIPInfoIfNeeded(ctx, ips.IPv6)
	}

	// STEP 2: Health check (rest remains the same)
	available, responseTime, version, err := s.client.CheckHealth(ctx, ep.Endpoint)
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
	} else if desc != nil && desc.DID != "" {
		s.db.UpdateEndpointServerDID(ctx, ep.ID, desc.DID)
	}

	// Fetch repos with full info
	repoList, err := s.client.ListRepos(ctx, ep.Endpoint)
	if err != nil {
		log.Verbose("Warning: failed to list repos for %s: %v", ep.Endpoint, err)
		repoList = []Repo{}
	}

	// Convert to DIDs for backward compatibility
	dids := make([]string, len(repoList))
	for i, repo := range repoList {
		dids[i] = repo.DID
	}

	// STEP 4: SAVE scan result
	s.saveScanResult(ctx, ep.ID, &ScanResult{
		Status:       storage.EndpointStatusOnline,
		ResponseTime: responseTime,
		Description:  desc,
		DIDs:         dids,
		Version:      version,
	})

	// Save repos in batches (only tracks changes)
	if len(repoList) > 0 {
		batchSize := 10000

		log.Verbose("Processing %d repos for %s (tracking changes only)", len(repoList), ep.Endpoint)

		for i := 0; i < len(repoList); i += batchSize {
			end := i + batchSize
			if end > len(repoList) {
				end = len(repoList)
			}

			batch := repoList[i:end]
			repoData := make([]storage.PDSRepoData, len(batch))

			for j, repo := range batch {
				active := true
				if repo.Active != nil {
					active = *repo.Active
				}

				status := ""
				if repo.Status != nil {
					status = *repo.Status
				}

				repoData[j] = storage.PDSRepoData{
					DID:    repo.DID,
					Head:   repo.Head,
					Rev:    repo.Rev,
					Active: active,
					Status: status,
				}
			}

			if err := s.db.UpsertPDSRepos(ctx, ep.ID, repoData); err != nil {
				log.Error("Failed to save repo batch for endpoint %d: %v", ep.ID, err)
			}
		}

		log.Verbose("✓ Processed %d repos for %s", len(repoList), ep.Endpoint)
	}

	// IP info fetch already started at the beginning (step 1.5)
	// It will complete in the background
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
