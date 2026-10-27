package smbwire

import (
	"errors"
	"net"
	"testing"
)

type panickingExchangeConn struct {
	*responseConn
	stage   string
	failure any
}

func (c *panickingExchangeConn) Read(p []byte) (int, error) {
	if c.stage == "read" {
		panic(c.failure)
	}
	return c.responseConn.Read(p)
}

func (c *panickingExchangeConn) Write(p []byte) (int, error) {
	if c.stage == "write" {
		panic(c.failure)
	}
	return c.responseConn.Write(p)
}

func TestExchangePanicClosesTransportBeforeUnwinding(t *testing.T) {
	for _, stage := range []string{"before I/O", "write", "read"} {
		t.Run(stage, func(t *testing.T) {
			c, wire := connectionWithResponse(5, 9, 0, nil)
			failure := errors.New("fixture exchange panic")
			c.wire = &panickingExchangeConn{wire, stage, failure}
			if stage == "before I/O" {
				c.opts.BeforeIO = func() error { panic(failure) }
			}
			var caught any
			func() {
				defer func() { caught = recover() }()
				_, _ = c.exchange(5, 9, nil)
			}()
			if caught != failure {
				t.Fatalf("exchange changed the panic: got %v, want original %v", caught, failure)
			}
			if !c.IsClosed() || !wire.closed || wire.closeCalls != 1 {
				t.Fatalf("panic left transport reusable: client closed=%t, transport closed=%t, close calls=%d", c.IsClosed(), wire.closed, wire.closeCalls)
			}
			writes := wire.writes
			if _, err := c.exchange(4, 9, nil); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("cleanup after panic reused the transport: %v", err)
			}
			c.Close()
			if wire.writes != writes || wire.closeCalls != 1 {
				t.Fatalf("cleanup after panic repeated I/O: writes=%d, want %d; close calls=%d", wire.writes, writes, wire.closeCalls)
			}
		})
	}
}
