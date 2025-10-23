package monitor

import (
	"sync"
	"time"
)

type JobStatus struct {
	Name         string        `json:"name"`
	Status       string        `json:"status"` // "idle", "running", "completed", "error"
	StartTime    time.Time     `json:"start_time,omitempty"`
	LastRun      time.Time     `json:"last_run,omitempty"`
	Duration     time.Duration `json:"duration,omitempty"`
	Progress     *Progress     `json:"progress,omitempty"`
	Error        string        `json:"error,omitempty"`
	NextRun      time.Time     `json:"next_run,omitempty"`
	RunCount     int64         `json:"run_count"`
	SuccessCount int64         `json:"success_count"`
	ErrorCount   int64         `json:"error_count"`
}

type Progress struct {
	Current int     `json:"current"`
	Total   int     `json:"total"`
	Percent float64 `json:"percent"`
	Message string  `json:"message,omitempty"`
}

type WorkerStatus struct {
	ID          int           `json:"id"`
	Status      string        `json:"status"` // "idle", "working"
	CurrentTask string        `json:"current_task,omitempty"`
	StartedAt   time.Time     `json:"started_at,omitempty"`
	Duration    time.Duration `json:"duration,omitempty"`
}

type Tracker struct {
	mu      sync.RWMutex
	jobs    map[string]*JobStatus
	workers map[string][]WorkerStatus // key is job name
}

var globalTracker *Tracker

func init() {
	globalTracker = &Tracker{
		jobs:    make(map[string]*JobStatus),
		workers: make(map[string][]WorkerStatus),
	}
}

func GetTracker() *Tracker {
	return globalTracker
}

// Job status methods
func (t *Tracker) RegisterJob(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.jobs[name] = &JobStatus{
		Name:   name,
		Status: "idle",
	}
}

func (t *Tracker) StartJob(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if job, exists := t.jobs[name]; exists {
		job.Status = "running"
		job.StartTime = time.Now()
		job.Error = ""
		job.RunCount++
	}
}

func (t *Tracker) CompleteJob(name string, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if job, exists := t.jobs[name]; exists {
		job.LastRun = time.Now()
		job.Duration = time.Since(job.StartTime)

		if err != nil {
			job.Status = "error"
			job.Error = err.Error()
			job.ErrorCount++
		} else {
			job.Status = "completed"
			job.SuccessCount++
		}

		job.Progress = nil // Clear progress
	}
}

func (t *Tracker) UpdateProgress(name string, current, total int, message string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if job, exists := t.jobs[name]; exists {
		var percent float64
		if total > 0 {
			percent = float64(current) / float64(total) * 100
		}

		job.Progress = &Progress{
			Current: current,
			Total:   total,
			Percent: percent,
			Message: message,
		}
	}
}

func (t *Tracker) SetNextRun(name string, nextRun time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if job, exists := t.jobs[name]; exists {
		job.NextRun = nextRun
	}
}

func (t *Tracker) GetJobStatus(name string) *JobStatus {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if job, exists := t.jobs[name]; exists {
		// Create a copy
		jobCopy := *job
		if job.Progress != nil {
			progressCopy := *job.Progress
			jobCopy.Progress = &progressCopy
		}

		// Calculate duration for running jobs
		if jobCopy.Status == "running" {
			jobCopy.Duration = time.Since(jobCopy.StartTime)
		}

		return &jobCopy
	}
	return nil
}

func (t *Tracker) GetAllJobs() map[string]*JobStatus {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make(map[string]*JobStatus)
	for name, job := range t.jobs {
		jobCopy := *job
		if job.Progress != nil {
			progressCopy := *job.Progress
			jobCopy.Progress = &progressCopy
		}

		// Calculate duration for running jobs
		if jobCopy.Status == "running" {
			jobCopy.Duration = time.Since(jobCopy.StartTime)
		}

		result[name] = &jobCopy
	}
	return result
}

// Worker status methods
func (t *Tracker) InitWorkers(jobName string, count int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	workers := make([]WorkerStatus, count)
	for i := 0; i < count; i++ {
		workers[i] = WorkerStatus{
			ID:     i + 1,
			Status: "idle",
		}
	}
	t.workers[jobName] = workers
}

func (t *Tracker) StartWorker(jobName string, workerID int, task string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if workers, exists := t.workers[jobName]; exists && workerID > 0 && workerID <= len(workers) {
		workers[workerID-1].Status = "working"
		workers[workerID-1].CurrentTask = task
		workers[workerID-1].StartedAt = time.Now()
	}
}

func (t *Tracker) CompleteWorker(jobName string, workerID int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if workers, exists := t.workers[jobName]; exists && workerID > 0 && workerID <= len(workers) {
		workers[workerID-1].Status = "idle"
		workers[workerID-1].CurrentTask = ""
		workers[workerID-1].Duration = time.Since(workers[workerID-1].StartedAt)
		workers[workerID-1].StartedAt = time.Time{}
	}
}

func (t *Tracker) GetWorkers(jobName string) []WorkerStatus {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if workers, exists := t.workers[jobName]; exists {
		// Create a copy with calculated durations
		result := make([]WorkerStatus, len(workers))
		for i, w := range workers {
			result[i] = w
			if w.Status == "working" && !w.StartedAt.IsZero() {
				result[i].Duration = time.Since(w.StartedAt)
			}
		}
		return result
	}
	return nil
}
