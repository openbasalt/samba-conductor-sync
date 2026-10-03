package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"sort"
	"sync"
	"time"

	"github.com/openbasalt/samba-conductor-sync/syncapi"
)

// maxJobs bounds the finished jobs kept in memory.
const maxJobs = 50

// jobs tracks background plans and applies; one runs at a time.
type jobs struct {
	mu      sync.Mutex
	byID    map[string]*syncapi.Job
	running string
	wg      sync.WaitGroup
}

func newJobs() *jobs { return &jobs{byID: map[string]*syncapi.Job{}} }

func newID() string {
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// start registers and runs a job unless one is running. fn gets a setter
// for the run ID and returns the run's status and error.
func (j *jobs) start(base context.Context, kind, actor string, now func() time.Time,
	fn func(ctx context.Context, setRun func(int64)) (string, error)) (*syncapi.Job, bool) {
	j.mu.Lock()
	if j.running != "" {
		cur := *j.byID[j.running]
		j.mu.Unlock()
		return &cur, false
	}
	job := &syncapi.Job{ID: newID(), Kind: kind, State: syncapi.JobRunning, Actor: actor, StartedAt: now().UTC()}
	j.byID[job.ID] = job
	j.running = job.ID
	j.prune()
	snapshot := *job
	j.mu.Unlock()
	j.wg.Add(1)
	go func() {
		defer j.wg.Done()
		status, err := fn(base, func(id int64) {
			j.mu.Lock()
			job.RunID = id
			j.mu.Unlock()
		})
		j.mu.Lock()
		defer j.mu.Unlock()
		job.FinishedAt = now().UTC()
		job.RunStatus = status
		switch {
		case err == nil:
			job.State = syncapi.JobDone
		case job.RunID != 0 && status != "":
			// The run completed with an outcome the engine reports as an
			// error (blocked at the limits, partial, dry-run, plan
			// changed): the job is done; the run says what happened.
			job.State, job.Error = syncapi.JobDone, err.Error()
		default:
			job.State, job.Error = syncapi.JobFailed, err.Error()
		}
		j.running = ""
	}()
	return &snapshot, true
}

// prune drops the oldest finished jobs beyond maxJobs (caller holds mu).
func (j *jobs) prune() {
	if len(j.byID) <= maxJobs {
		return
	}
	var done []*syncapi.Job
	for _, x := range j.byID {
		if x.State != syncapi.JobRunning {
			done = append(done, x)
		}
	}
	sort.Slice(done, func(a, b int) bool { return done[a].StartedAt.Before(done[b].StartedAt) })
	for i := 0; i < len(done) && len(j.byID) > maxJobs; i++ {
		delete(j.byID, done[i].ID)
	}
}

func (j *jobs) get(id string) (syncapi.Job, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	x, ok := j.byID[id]
	if !ok {
		return syncapi.Job{}, false
	}
	return *x, true
}

func (j *jobs) current() *syncapi.Job {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.running == "" {
		return nil
	}
	x := *j.byID[j.running]
	return &x
}

// wait waits for running jobs to stop, at most d.
func (j *jobs) wait(d time.Duration) {
	done := make(chan struct{})
	go func() { j.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
	}
}
