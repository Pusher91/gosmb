package main

import (
	"context"
	"time"
)

// The scheduler and direct scanner calls both enforce a per-host budget. Reuse
// an earlier inherited deadline so a scheduled scan does not allocate another
// cancel context. Its caller retains ownership of the inherited context.
func withHostTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 || ctx.Err() != nil {
		return ctx, func() {}
	}
	deadline := time.Now().Add(timeout)
	if inherited, ok := ctx.Deadline(); ok && !inherited.After(deadline) {
		return ctx, func() {}
	}
	return context.WithDeadline(ctx, deadline)
}
