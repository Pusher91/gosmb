package main

import (
	"context"
	"sync"
	"time"
)

type hostScanOutcome struct {
	result    Result
	completed bool
	started   bool
}

// Each host gets its own deadline when its scan starts, not while queued.
// A host deadline completes that attempt; cancellation of the whole run does not.
func runHostScan(ctx context.Context, target Target, opts Options, scan func(context.Context, Target, Options) Result) hostScanOutcome {
	hostCtx := ctx
	cancel := func() {}
	if opts.HostTimeout > 0 {
		hostCtx, cancel = context.WithTimeout(ctx, opts.HostTimeout)
	}
	defer cancel()
	result := scan(hostCtx, target, opts)
	completed := ctx.Err() == nil
	if completed && hostCtx.Err() == context.DeadlineExceeded {
		markHostTimeout(&result)
	}
	return hostScanOutcome{result: result, completed: completed, started: true}
}

// Only the coordinator calls emit. Workers never touch output or progress.
// Slots stay occupied until a result has been emitted, preserving streaming
// order even at concurrency=1 and stopping launches promptly on output errors.
func scanTargets(ctx context.Context, targets []Target, opts Options, concurrency int, delay time.Duration,
	scan func(context.Context, Target, Options) Result, emit func(Result, bool) error) error {
	if len(targets) == 0 {
		return nil
	}
	limit := min(max(concurrency, 1), len(targets))
	workCtx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() {
		cancel()
		workers.Wait()
	}()
	finished := make(chan hostScanOutcome, limit)
	next, active := 0, 0
	var nextStart time.Time
	var outputErr error
	stopping := false
	ctxDone := ctx.Done()
	accept := func(outcome hostScanOutcome) {
		active--
		if !outcome.started {
			return
		}
		if outputErr == nil {
			outputErr = emit(outcome.result, outcome.completed)
			if outputErr != nil {
				stopping = true
				ctxDone = nil
				cancel()
			}
		}
	}
	for active > 0 || (!stopping && next < len(targets)) {
		if ctx.Err() != nil && !stopping {
			stopping = true
			ctxDone = nil
			cancel()
		}
		if stopping && active == 0 {
			break
		}
		canStart := !stopping && next < len(targets) && active < limit
		if canStart && !time.Now().Before(nextStart) {
			// Prefer already finished hosts over filling another slot.
			select {
			case outcome := <-finished:
				accept(outcome)
				continue
			default:
			}
			target := targets[next]
			next++
			active++
			nextStart = time.Now().Add(delay)
			workers.Add(1)
			go func() {
				defer workers.Done()
				if workCtx.Err() != nil {
					// A cancellation between dispatch and scheduling must not
					// initiate another network connection or create a fake row.
					finished <- hostScanOutcome{}
					return
				}
				finished <- runHostScan(workCtx, target, opts, scan)
			}()
			continue
		}
		var timer *time.Timer
		var wake <-chan time.Time
		if canStart {
			timer = time.NewTimer(time.Until(nextStart))
			wake = timer.C
		}
		select {
		case outcome := <-finished:
			accept(outcome)
		case <-ctxDone:
			stopping = true
			ctxDone = nil
			cancel()
		case <-wake:
		}
		if timer != nil {
			timer.Stop()
		}
	}
	if outputErr != nil {
		return outputErr
	}
	return ctx.Err()
}
