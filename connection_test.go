package main

import (
	"context"
	"io"
	"net"
	"strconv"
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
	// The dependency's malformed IPv6 spelling must never be used for dialing.
	conn, err := d.DialContext(context.Background(), "tcp", "::1:1")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	<-accepted
}
