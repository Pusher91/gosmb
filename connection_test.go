package main

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestScanTargetTimesOutDuringSMBNegotiation(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		// Accept TCP, consume requests, and deliberately send no SMB reply.
		_, _ = io.Copy(io.Discard, conn)
	}()
	host, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	start := time.Now()
	result := scanTarget(context.Background(), Target{Host: host, Port: port}, Options{Username: "fixture", Password: "fixture-only", Timeout: 80 * time.Millisecond})
	if !result.Reachable || !result.TimedOut || result.Authentication != TimedOut || result.Enumeration != TimedOut || result.Error == "" {
		t.Fatalf("unexpected result from stalled server: %+v", result)
	}
	if time.Since(start) > time.Second {
		t.Fatal("SMB negotiation did not honor timeout")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("socket was not closed after timeout")
	}
}

func TestScanTargetCancellationClosesSocket(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		cancel()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = io.Copy(io.Discard, conn)
	}()
	host, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	start := time.Now()
	result := scanTarget(ctx, Target{Host: host, Port: port}, Options{Username: "fixture", Password: "fixture-only", Timeout: time.Minute})
	if result.TimedOut || result.Authentication == TimedOut || result.Enumeration == TimedOut || result.Authentication == "authenticated" || result.Error == "" {
		t.Fatalf("unexpected cancellation result: %+v", result)
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancellation did not interrupt negotiation")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("cancellation did not close socket")
	}
}

func TestDialerUsesExplicitIPv6Destination(t *testing.T) {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 loopback is unavailable")
	}
	defer listener.Close()
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		if conn, err := listener.Accept(); err == nil {
			conn.Close()
		}
	}()
	d := boundedDialer{ctx: context.Background(), target: listener.Addr().String(), timeout: time.Second}
	defer d.close()
	conn, err := d.Dial()
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	<-accepted
}

func TestDialerAllowsOnlyOneAttempt(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	d := &boundedDialer{ctx: context.Background(), target: listener.Addr().String(), timeout: time.Second}
	defer d.close()

	// Even concurrent callers cannot replace the first socket or trigger a retry.
	var callers sync.WaitGroup
	connections := make(chan net.Conn, 8)
	for range cap(connections) {
		callers.Go(func() {
			conn, _ := d.Dial()
			connections <- conn
		})
	}
	callers.Wait()
	close(connections)
	count := 0
	for conn := range connections {
		if conn != nil {
			count++
			defer conn.Close()
		}
	}
	if count != 1 {
		t.Fatalf("established %d TCP connections, want exactly one", count)
	}
}

func TestDialerDoesNotRetryFailedAttempt(t *testing.T) {
	d := &boundedDialer{ctx: context.Background(), target: "missing-port"}
	if _, err := d.Dial(); err == nil {
		t.Fatal("malformed endpoint unexpectedly connected")
	}
	if _, err := d.Dial(); err == nil || err.Error() != "SMB target already dialed" {
		t.Fatalf("failed dial permitted a second attempt: %v", err)
	}
}

func TestClientCloseStopsFurtherScannerOperations(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	d := &boundedDialer{ctx: context.Background(), conn: client, reached: true}
	conn := &trackedConn{Conn: client, owner: d}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(d.err(), net.ErrClosed) || !errors.Is(d.arm(), net.ErrClosed) {
		t.Fatal("client closed a failed transport without notifying the scanner")
	}
	if !d.reachable() {
		t.Fatal("closing a connection lost its established reachability")
	}
	if _, err := d.Dial(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed transport allowed another dial: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("repeated cleanup is not idempotent: %v", err)
	}
}
