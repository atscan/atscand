package worker

import (
	"context"
	"log"
	"sync"
	"time"
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
	log.Printf("Starting job: %s", job.Name)
	job.Fn()

	for {
		select {
		case <-ctx.Done():
			log.Printf("Stopping job: %s", job.Name)
			return
		case <-ticker.C:
			log.Printf("Running job: %s", job.Name)
			job.Fn()
		}
	}
}
