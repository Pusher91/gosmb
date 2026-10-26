package main

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// boundedDialer retains the socket so cancellation and deadlines cover SMB
// negotiation, authentication and RPC, not just the initial TCP connection.
// It is passed directly to the in-repository SMB client.
type boundedDialer struct {
	ctx        context.Context
	target     string
	timeout    time.Duration
	mu         sync.Mutex
	conn       net.Conn
	attempted  bool
	closed     bool
	reached    bool
	peerIP     string
	timeoutErr error
}

// Retain typed timeouts at the socket boundary so protocol error wrapping
// cannot lose their classification.
type trackedConn struct {
	net.Conn
	owner *boundedDialer
}

func (c *trackedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.owner.recordTimeout(err)
	return n, err
}

func (c *trackedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.owner.recordTimeout(err)
	return n, err
}

// A protocol failure closes the client connection directly. Keep the owner in
// sync so the scanner stops issuing operations on the poisoned transport.
func (c *trackedConn) Close() error { return c.owner.closeSocket() }

func (d *boundedDialer) recordTimeout(err error) {
	var networkError net.Error
	if !errors.Is(err, context.DeadlineExceeded) && !(errors.As(err, &networkError) && networkError.Timeout()) {
		return
	}
	d.mu.Lock()
	if d.timeoutErr == nil {
		d.timeoutErr = err
	}
	d.mu.Unlock()
	// A timed-out SMB exchange cannot safely be retried on the same stream.
	d.close()
}

func (d *boundedDialer) timedOut() bool {
	if errors.Is(d.ctx.Err(), context.DeadlineExceeded) {
		return true
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.timeoutErr != nil
}

func (d *boundedDialer) err() error {
	if err := d.ctx.Err(); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timeoutErr != nil {
		return d.timeoutErr
	}
	if d.closed {
		return net.ErrClosed
	}
	return nil
}

func (d *boundedDialer) Dial() (net.Conn, error) {
	d.mu.Lock()
	if err := d.ctx.Err(); err != nil {
		d.mu.Unlock()
		return nil, err
	}
	if d.closed {
		d.mu.Unlock()
		return nil, net.ErrClosed
	}
	if d.attempted {
		d.mu.Unlock()
		return nil, errors.New("SMB target already dialed")
	}
	d.attempted = true
	d.mu.Unlock()

	// Try resolved addresses serially and stop at the first success. Disabling
	// parallel IPv4/IPv6 racing prevents a second connected socket while keeping
	// hostname fallback within the same connection timeout and host context.
	c, err := (&net.Dialer{Timeout: d.timeout, FallbackDelay: -1}).DialContext(d.ctx, "tcp", d.target)
	if err != nil {
		d.recordTimeout(err)
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.reached = true
	d.peerIP, _, _ = net.SplitHostPort(c.RemoteAddr().String())
	if d.closed || d.ctx.Err() != nil {
		c.Close()
		if err := d.ctx.Err(); err != nil {
			return nil, err
		}
		return nil, net.ErrClosed
	}
	if err := c.SetDeadline(d.deadline()); err != nil {
		c.Close()
		return nil, err
	}
	d.conn = c
	return &trackedConn{Conn: c, owner: d}, nil
}

func (d *boundedDialer) deadline() time.Time {
	var end time.Time
	if d.timeout > 0 {
		end = time.Now().Add(d.timeout)
	}
	if deadline, ok := d.ctx.Deadline(); ok && (end.IsZero() || deadline.Before(end)) {
		return deadline
	}
	return end
}

func (d *boundedDialer) arm() error {
	if err := d.ctx.Err(); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timeoutErr != nil {
		return d.timeoutErr
	}
	if d.closed || d.conn == nil {
		return net.ErrClosed
	}
	return d.conn.SetDeadline(d.deadline())
}

func (d *boundedDialer) close() {
	_ = d.closeSocket()
}

func (d *boundedDialer) closeSocket() error {
	d.mu.Lock()
	c := d.conn
	d.closed, d.conn = true, nil
	d.mu.Unlock()
	if c != nil {
		return c.Close()
	}
	return nil
}

func (d *boundedDialer) reachable() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.reached
}

func (d *boundedDialer) serverIP() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.peerIP
}
