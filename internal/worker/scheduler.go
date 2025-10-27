package worker

import (
	"context"
	"sync"
	"time"

	"github.com/atscan/atscand/internal/log"
	"github.com/atscan/atscand/internal/monitor"
)

type Job struct {
	Name     string
	Interval time.Duration
	Fn       func()
}

type Scheduler struct {
	jobs []*Job
	mu   sync.Mutex
}

func NewScheduler() *Scheduler {
	return &Scheduler{
		jobs: make([]*Job, 0),
	}
}

func (s *Scheduler) AddJob(name string, interval time.Duration, fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.jobs = append(s.jobs, &Job{
		Name:     name,
		Interval: interval,
		Fn:       fn,
	})

	// Register job with tracker
	monitor.GetTracker().RegisterJob(name)
}

func (s *Scheduler) Start(ctx context.Context) {
	s.mu.Lock()
	jobs := s.jobs
	s.mu.Unlock()

	for _, job := range jobs {
		go s.runJob(ctx, job)
	}
}

func (s *Scheduler) runJob(ctx context.Context, job *Job) {
	ticker := time.NewTicker(job.Interval)
	defer ticker.Stop()

	// Run immediately
	log.Info("Starting job: %s", job.Name)
	s.executeJob(job)

	for {
		// Set next run time
		monitor.GetTracker().SetNextRun(job.Name, time.Now().Add(job.Interval))

		select {
		case <-ctx.Done():
			log.Info("Stopping job: %s", job.Name)
			return
		case <-ticker.C:
			log.Info("Running job: %s", job.Name)
			s.executeJob(job)
		}
	}
}

func (s *Scheduler) executeJob(job *Job) {
	monitor.GetTracker().StartJob(job.Name)

	// Run job and capture any panic
	func() {
		defer func() {
			if r := recover(); r != nil {
				log.Error("Job %s panicked: %v", job.Name, r)
				monitor.GetTracker().CompleteJob(job.Name, nil)
			}
		}()

		job.Fn()
		monitor.GetTracker().CompleteJob(job.Name, nil)
	}()
}
