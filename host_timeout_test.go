package main

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"
)

func TestHostTimeoutReusesEarlierAndEqualDeadlines(t *testing.T) {
	for _, budget := range []time.Duration{5 * time.Second, 10 * time.Second} {
		t.Run(budget.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				start := time.Now()
				parent, cancelParent := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancelParent()
				child, cancelChild := withHostTimeout(parent, budget)
				if child != parent {
					t.Fatal("an inherited earlier/equal deadline allocated a child context")
				}
				cancelChild()
				if parent.Err() != nil {
					t.Fatal("releasing a reused context canceled its owner")
				}
				<-child.Done()
				if !errors.Is(child.Err(), context.DeadlineExceeded) || time.Since(start) != 5*time.Second {
					t.Fatalf("inherited host deadline was lost: %v", child.Err())
				}
			})
		})
	}
}

func TestHostTimeoutAddsShorterBudgetWithoutCancelingParent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		parent, cancelParent := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelParent()
		start := time.Now()
		child, cancelChild := withHostTimeout(parent, 5*time.Second)
		defer cancelChild()
		if deadline, ok := child.Deadline(); !ok || deadline != start.Add(5*time.Second) {
			t.Fatalf("host budget did not start at invocation: deadline=%v, present=%v", deadline, ok)
		}
		<-child.Done()
		if !errors.Is(child.Err(), context.DeadlineExceeded) || parent.Err() != nil {
			t.Fatalf("host timeout affected its parent: child=%v parent=%v", child.Err(), parent.Err())
		}
	})
}

func TestHostTimeoutContextOwnershipAndCancellation(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	for _, budget := range []time.Duration{0, -time.Second} {
		child, cancelChild := withHostTimeout(parent, budget)
		cancelChild()
		if child != parent || parent.Err() != nil {
			t.Fatal("disabled host timeout replaced or canceled its parent")
		}
	}
	child, cancelChild := withHostTimeout(parent, time.Minute)
	cancelChild()
	if !errors.Is(child.Err(), context.Canceled) || parent.Err() != nil {
		t.Fatalf("child cancellation affected its parent: child=%v parent=%v", child.Err(), parent.Err())
	}
	child, cancelChild = withHostTimeout(parent, time.Minute)
	defer cancelChild()
	cancelParent()
	if !errors.Is(child.Err(), context.Canceled) {
		t.Fatalf("user cancellation did not reach the host: %v", child.Err())
	}
	child, cancelChild = withHostTimeout(parent, time.Minute)
	cancelChild()
	if child != parent || !errors.Is(child.Err(), context.Canceled) {
		t.Fatal("an already canceled context was replaced or revived")
	}
}
