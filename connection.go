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
// It is passed through the library's ProxyDialer interface; it is not a proxy.
type boundedDialer struct {
	ctx        context.Context
	target     string
	timeout    time.Duration
	mu         sync.Mutex
	conn       net.Conn
	closed     bool
	reached    bool
	peerIP     string
	timeoutErr error
}

// The SMB library does not consistently wrap underlying I/O errors. Retain
// typed timeouts at the socket boundary instead of guessing from error text.
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

func (d *boundedDialer) recordTimeout(err error) {
	var networkError net.Error
	if !errors.Is(err, context.DeadlineExceeded) && !(errors.As(err, &networkError) && networkError.Timeout()) {
		return
	}
	d.mu.Lock()
	if d.timeoutErr == nil {
		d.timeoutErr = err
	}
	c := d.conn
	d.mu.Unlock()
	// A timed-out SMB exchange cannot safely be retried on the same stream.
	if c != nil {
		_ = c.Close()
	}
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

func (d *boundedDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(d.ctx, network, address)
}

func (d *boundedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dialCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(d.ctx, cancel)
	defer cancel()
	defer stop()
	// Keep the dial destination tied to the explicit user target. In particular,
	// the library formats IPv6 addresses without brackets; JoinHostPort was
	// already applied when this dialer was constructed.
	if d.target != "" {
		address = d.target
	}
	c, err := (&net.Dialer{Timeout: d.timeout}).DialContext(dialCtx, network, address)
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
	d.conn = c
	if err := c.SetDeadline(d.deadline()); err != nil {
		c.Close()
		return nil, err
	}
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
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	if d.conn != nil {
		d.conn.Close()
	}
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
