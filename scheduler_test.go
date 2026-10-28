package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestSchedulerDelayAfterCompletedWorkers(t *testing.T) {
	for _, interrupted := range []bool{false, true} {
		name := "complete"
		if interrupted {
			name = "cancel_during_delay"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				const delay = time.Second
				if interrupted {
					timer := time.AfterFunc(delay/2, cancel)
					defer timer.Stop()
				}
				targets := make([]Target, 3)
				started := make(chan time.Time, len(targets))
				start := time.Now()
				emitted := 0
				err := scanTargets(ctx, targets, Options{}, len(targets), delay,
					func(context.Context, Target, Options) Result {
						started <- time.Now()
						return Result{}
					}, func(Result, bool) error { emitted++; return nil })
				wantCount, wantElapsed := len(targets), 2*delay
				var wantErr error
				if interrupted {
					wantCount, wantElapsed = 1, delay/2
					wantErr = context.Canceled
				}
				if !errors.Is(err, wantErr) {
					t.Fatalf("scheduler error = %v; want %v", err, wantErr)
				}
				if len(started) != wantCount || emitted != wantCount || time.Since(start) != wantElapsed {
					t.Fatalf("started=%d emitted=%d elapsed=%v; want %d hosts in %v", len(started), emitted, time.Since(start), wantCount, wantElapsed)
				}
				for i := range wantCount {
					if elapsed := (<-started).Sub(start); elapsed != time.Duration(i)*delay {
						t.Errorf("launch %d at %v; want %v", i, elapsed, time.Duration(i)*delay)
					}
				}
			})
		})
	}
}

func BenchmarkSchedulerDelayedStarts(b *testing.B) {
	targets := make([]Target, 32)
	scan := func(context.Context, Target, Options) Result { return Result{} }
	emit := func(Result, bool) error { return nil }
	for _, tc := range []struct {
		name        string
		concurrency int
	}{{"serial", 1}, {"concurrent", 4}} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if err := scanTargets(context.Background(), targets, Options{}, tc.concurrency, 100*time.Microsecond, scan, emit); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// These tests use the public CLI boundary so launch order, output, and progress
// are verified together. Writers are synchronized for observations during scans.
type schedulerCapture struct {
	mu     sync.Mutex
	buffer bytes.Buffer
	writes chan string
}

func (w *schedulerCapture) Write(p []byte) (int, error) {
	w.mu.Lock()
	n, err := w.buffer.Write(p)
	w.mu.Unlock()
	if w.writes != nil {
		select {
		case w.writes <- string(p):
		default:
		}
	}
	return n, err
}

func (w *schedulerCapture) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buffer.String()
}

func schedulerHostFile(t *testing.T, names ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(path, []byte(strings.Join(names, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func schedulerSuccess(target Target) Result {
	return Result{Target: target.String(), ServerIP: "192.0.2.1", Reachable: true, Authentication: "authenticated", Enumeration: "ok", Shares: []ShareResult{{Name: target.Host + "-share", Read: Allowed, Write: Denied}}}
}

func TestCLIDefaultConcurrencyAndSerialOverride(t *testing.T) {
	for _, tc := range []struct {
		name          string
		hosts, active int
		flags         []string
	}{
		{"default", 43, 40, nil},
		{"small list", 3, 3, nil},
		{"serial override", 3, 1, []string{"--concurrency=1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hosts := make([]string, tc.hosts)
			for i := range hosts {
				hosts[i] = "host-" + strconv.Itoa(i)
			}
			path := schedulerHostFile(t, hosts...)
			synctest.Test(t, func(t *testing.T) {
				var out, diagnostics bytes.Buffer
				deps := testCLIDeps(&out, &diagnostics)
				started := make(chan struct{}, tc.hosts)
				release := make(chan struct{})
				releaseAll := sync.OnceFunc(func() { close(release) })
				defer releaseAll()
				deps.scan = func(_ context.Context, target Target, _ Options) Result {
					started <- struct{}{}
					<-release
					return schedulerSuccess(target)
				}
				args := append([]string{path, "-u", "alice", "-p", "", "--tsv"}, tc.flags...)
				done := make(chan int, 1)
				go func() { done <- runCLI(context.Background(), args, deps) }()
				// All launched scans are blocked on release, so the initial batch
				// directly demonstrates the CLI's concurrency bound without timing.
				synctest.Wait()
				if got := len(started); got != tc.active {
					t.Fatalf("started %d hosts before any completed; want %d", got, tc.active)
				}
				releaseAll()
				if code := <-done; code != 0 {
					t.Fatalf("scan failed: exit=%d stderr=%q", code, diagnostics.String())
				}
				if len(started) != tc.hosts || len(parseTestTSV(t, out.String())) != tc.hosts+1 {
					t.Fatalf("queued hosts or output were lost: started=%d stdout=%q", len(started), out.String())
				}
			})
		})
	}
}

func awaitSchedulerStart(t *testing.T, ctx context.Context, started <-chan string) string {
	t.Helper()
	select {
	case host := <-started:
		return host
	case <-ctx.Done():
		t.Fatal("scheduler did not launch the expected worker")
		return ""
	}
}

func awaitSchedulerDone(t *testing.T, ctx context.Context, done <-chan int) int {
	t.Helper()
	select {
	case code := <-done:
		return code
	case <-ctx.Done():
		t.Fatal("scheduler did not terminate")
		return -1
	}
}

func TestSchedulerBoundsOverlapAndEmitsCompletionOrder(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	path := schedulerHostFile(t, "first", "second", "third", "fourth")
	out := &schedulerCapture{writes: make(chan string, 16)}
	errOut := &schedulerCapture{}
	deps := testCLIDeps(out, errOut)
	started := make(chan string, 4)
	release := map[string]chan struct{}{}
	for _, host := range []string{"first", "second", "third", "fourth"} {
		release[host] = make(chan struct{})
	}
	var active, maximum atomic.Int32
	deps.scan = func(scanCtx context.Context, target Target, _ Options) Result {
		current := active.Add(1)
		for old := maximum.Load(); current > old && !maximum.CompareAndSwap(old, current); old = maximum.Load() {
		}
		defer active.Add(-1)
		started <- target.Host
		select {
		case <-release[target.Host]:
			return schedulerSuccess(target)
		case <-scanCtx.Done():
			return Result{Target: target.String(), Error: scanCtx.Err().Error()}
		}
	}
	done := make(chan int, 1)
	go func() {
		done <- runCLI(ctx, []string{path, "-u", "alice", "-p", "", "--concurrency", "2", "--delay", "0", "--tsv"}, deps)
	}()
	firstTwo := map[string]bool{awaitSchedulerStart(t, ctx, started): true, awaitSchedulerStart(t, ctx, started): true}
	if !firstTwo["first"] || !firstTwo["second"] || active.Load() != 2 {
		t.Fatalf("workers did not overlap within limit: %v active=%d", firstTwo, active.Load())
	}
	close(release["second"])
	for !strings.Contains(out.String(), "second-share") {
		select {
		case <-out.writes:
		case <-ctx.Done():
			t.Fatal("fast second result was blocked behind slow first result")
		}
	}
	if strings.Contains(out.String(), "first-share") {
		t.Fatal("first result was emitted before its scan completed")
	}
	close(release["first"])
	close(release["third"])
	close(release["fourth"])
	if code := awaitSchedulerDone(t, ctx, done); code != 0 {
		t.Fatalf("scan failed: %d %s", code, errOut.String())
	}
	if maximum.Load() != 2 || active.Load() != 0 {
		t.Fatalf("wrong active-worker bound or leaked worker: max=%d active=%d", maximum.Load(), active.Load())
	}
	rows := parseTestTSV(t, out.String())
	if len(rows) != 5 || rows[1][1] != "second-share" {
		t.Fatalf("results were not emitted in completion order: %#v", rows)
	}
	for _, host := range []string{"first", "second", "third", "fourth"} {
		if strings.Count(out.String(), host+"-share") != 1 {
			t.Fatalf("missing/duplicated result for %s: %q", host, out.String())
		}
	}
}

func TestHostTimeoutReleasesSlotAndBudgetStartsWhenWorkerRuns(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	path := schedulerHostFile(t, "slow", "queued")
	out, errOut := &schedulerCapture{}, &schedulerCapture{}
	deps := testCLIDeps(out, errOut)
	deps.stdoutIsTerminal, deps.stderrIsTerminal = true, true
	const budget = time.Second
	remaining := make(chan time.Duration, 1)
	issues := make(chan string, 8)
	deps.scan = func(scanCtx context.Context, target Target, _ Options) Result {
		if target.Host == "slow" {
			<-scanCtx.Done()
			if !errors.Is(scanCtx.Err(), context.DeadlineExceeded) {
				issues <- "slow host did not reach its own deadline"
			}
			return Result{Target: target.String(), Authentication: "not_attempted", Enumeration: "not_attempted", Error: scanCtx.Err().Error()}
		}
		deadline, ok := scanCtx.Deadline()
		if !ok {
			issues <- "queued worker has no host deadline"
		} else {
			remaining <- time.Until(deadline)
		}
		select {
		case <-time.After(budget / 3):
			return schedulerSuccess(target)
		case <-scanCtx.Done():
			return Result{Target: target.String(), Error: "queued target inherited an expired host budget"}
		}
	}
	code := runCLI(ctx, []string{path, "-u", "alice", "-p", "", "--concurrency", "1", "--host-timeout", "1", "--delay", "0", "--json"}, deps)
	if code != 1 {
		t.Fatalf("timed-out host must set exit1: %d", code)
	}
	select {
	case issue := <-issues:
		t.Fatal(issue)
	default:
	}
	select {
	case left := <-remaining:
		if left < budget/2 {
			t.Fatalf("queued host lost its timeout while waiting: %v", left)
		}
	default:
		t.Fatal("queued host never ran")
	}
	var results []Result
	if err := json.Unmarshal([]byte(out.String()), &results); err != nil || len(results) != 2 {
		t.Fatalf("invalid timeout JSON: %v %q", err, out.String())
	}
	if !results[0].TimedOut || results[1].TimedOut || results[1].Authentication != "authenticated" || results[1].Enumeration != "ok" {
		t.Fatalf("timeout prevented queued work or was not marked: %#v", results)
	}
	if !strings.Contains(errOut.String(), "Progress: 100% (2/2 hosts completed)") || strings.Contains(errOut.String(), "(interrupted)") {
		t.Fatalf("host timeout incorrectly counted as user interruption: %q", errOut.String())
	}
}

func TestSchedulerCancellationStopsActiveWorkersAndQueuedStarts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watch, stopWatch := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopWatch()
	path := schedulerHostFile(t, "first", "second", "queued", "last")
	out, errOut := &schedulerCapture{}, &schedulerCapture{}
	deps := testCLIDeps(out, errOut)
	deps.stdoutIsTerminal, deps.stderrIsTerminal = true, true
	started := make(chan string, 4)
	var calls, active atomic.Int32
	deps.scan = func(scanCtx context.Context, target Target, _ Options) Result {
		calls.Add(1)
		active.Add(1)
		defer active.Add(-1)
		started <- target.Host
		<-scanCtx.Done()
		return Result{Target: target.String(), Authentication: "not_attempted", Enumeration: "not_attempted", Error: scanCtx.Err().Error()}
	}
	done := make(chan int, 1)
	go func() {
		done <- runCLI(ctx, []string{path, "-u", "alice", "-p", "", "--concurrency", "2", "--delay", "0"}, deps)
	}()
	awaitSchedulerStart(t, watch, started)
	awaitSchedulerStart(t, watch, started)
	cancel()
	if code := awaitSchedulerDone(t, watch, done); code != 1 {
		t.Fatalf("cancellation must fail run: %d", code)
	}
	if calls.Load() != 2 || active.Load() != 0 {
		t.Fatalf("canceled scheduler launched queued work or left workers running: calls=%d active=%d", calls.Load(), active.Load())
	}
	if !strings.Contains(errOut.String(), "Progress: 0% (0/4 hosts completed) (interrupted)") {
		t.Fatalf("canceled active workers were counted complete: %q", errOut.String())
	}
}

type schedulerFailingOutput struct {
	fail func()
	once sync.Once
}

func (w *schedulerFailingOutput) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "first-share") {
		w.once.Do(w.fail)
		return 0, io.ErrClosedPipe
	}
	return len(p), nil
}

func TestSchedulerOutputFailureCancelsActiveWorkers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	path := schedulerHostFile(t, "first", "second", "queued")
	secondStarted := make(chan struct{})
	outputFailed := make(chan struct{})
	errOut := &schedulerCapture{}
	deps := testCLIDeps(&schedulerFailingOutput{fail: func() { close(outputFailed) }}, errOut)
	var calls, active atomic.Int32
	deps.scan = func(scanCtx context.Context, target Target, _ Options) Result {
		calls.Add(1)
		active.Add(1)
		defer active.Add(-1)
		if target.Host == "first" {
			select {
			case <-secondStarted:
				return schedulerSuccess(target)
			case <-scanCtx.Done():
				return Result{Target: target.String(), Error: scanCtx.Err().Error()}
			}
		}
		if target.Host == "second" {
			close(secondStarted)
		}
		<-scanCtx.Done()
		return Result{Target: target.String(), Error: scanCtx.Err().Error()}
	}
	code := runCLI(ctx, []string{path, "-u", "alice", "-p", "", "--concurrency", "2", "--delay", "0"}, deps)
	select {
	case <-outputFailed:
	default:
		t.Fatal("output error path did not run")
	}
	if code != 1 || calls.Load() != 2 || active.Load() != 0 || ctx.Err() != nil {
		t.Fatalf("output failure did not promptly stop scheduling: code=%d calls=%d active=%d parent=%v", code, calls.Load(), active.Load(), ctx.Err())
	}
}

func TestSchedulerShortOutputStopsQueuedStarts(t *testing.T) {
	var diagnostics bytes.Buffer
	deps := testCLIDeps(shortOutputWriter{}, &diagnostics)
	calls := 0
	deps.scan = func(_ context.Context, target Target, _ Options) Result {
		calls++
		return schedulerSuccess(target)
	}
	targets := schedulerHostFile(t, "first", "queued")
	code := runCLI(context.Background(), []string{targets, "-u", "alice", "-p", "", "--no-header", "--delay=0", "--concurrency=1"}, deps)
	if code != 1 || calls != 1 {
		t.Fatalf("short output did not stop queued scans: exit=%d scans=%d", code, calls)
	}
}

func TestSchedulerDelaySpacesAllConcurrentLaunches(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	path := schedulerHostFile(t, "first", "second", "third")
	out, errOut := &schedulerCapture{}, &schedulerCapture{}
	deps := testCLIDeps(out, errOut)
	started := make(chan time.Time, 3)
	release := make(chan struct{})
	deps.scan = func(scanCtx context.Context, target Target, _ Options) Result {
		started <- time.Now()
		select {
		case <-release:
			return schedulerSuccess(target)
		case <-scanCtx.Done():
			return Result{Target: target.String(), Error: scanCtx.Err().Error()}
		}
	}
	done := make(chan int, 1)
	go func() {
		done <- runCLI(ctx, []string{path, "-u", "alice", "-p", "", "--concurrency", "3", "--delay", "50ms"}, deps)
	}()
	var launches []time.Time
	for len(launches) < 3 {
		select {
		case at := <-started:
			launches = append(launches, at)
		case <-ctx.Done():
			t.Fatal("global delay prevented concurrent launches")
		}
	}
	close(release)
	if code := awaitSchedulerDone(t, ctx, done); code != 0 {
		t.Fatalf("scan failed: %d", code)
	}
	for i := 1; i < len(launches); i++ {
		if gap := launches[i].Sub(launches[i-1]); gap < 40*time.Millisecond {
			t.Fatalf("--delay was not global between launches: %v", gap)
		}
	}
}
