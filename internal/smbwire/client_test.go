package smbwire

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSessionIdentityDistinguishesNullFromUserAndGuest(t *testing.T) {
	for _, tt := range []struct {
		name  string
		flags uint16
		want  int
	}{
		{"user", 0, AuthResultUser},
		{"guest", 1, AuthResultGuest},
		{"anonymous", 2, AuthResultAnonymous},
		{"encrypted_user", 4, AuthResultUser},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := &Connection{authenticated: true, sessionFlags: tt.flags, key: make([]byte, 16), signingKey: make([]byte, 16)}
			if got := c.AuthResult(); got != tt.want {
				t.Fatalf("session identity = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestSessionIdentityRequiresCompletedVerifiedAuthentication(t *testing.T) {
	for _, c := range []*Connection{
		{},
		{sessionFlags: 1},
		{authenticated: true},
		{authenticated: true, key: make([]byte, 16)},
		{authenticated: true, key: make([]byte, 16), signingKey: make([]byte, 15)},
		{authenticated: true, sessionFlags: 3, key: make([]byte, 16), signingKey: make([]byte, 16)},
	} {
		if got := c.AuthResult(); got != AuthResultUnverified {
			t.Errorf("incomplete/invalid authentication reported identity %d", got)
		}
	}
}

func TestConnectionUsesOneDialAttemptAndClosesFailedNegotiation(t *testing.T) {
	for _, failDial := range []bool{false, true} {
		attempts := 0
		dialFailure := errors.New("fixture dial failure")
		wire := &responseConn{Reader: bytes.NewReader(nil)}
		conn, err := NewConnection(Options{Dial: func() (net.Conn, error) {
			attempts++
			if failDial {
				return nil, dialFailure
			}
			return wire, nil
		}})
		if err == nil || conn != nil || attempts != 1 {
			t.Fatalf("failed connection: conn=%v, err=%v, attempts=%d", conn, err, attempts)
		}
		if failDial {
			if !errors.Is(err, dialFailure) {
				t.Fatalf("lost original dial failure: %v", err)
			}
		} else if !wire.closed {
			t.Fatal("failed negotiation left its connection open")
		}
	}
	if conn, err := NewConnection(Options{}); err == nil || conn != nil {
		t.Fatal("accepted an absent bounded dial function")
	}
}

func TestNTStatusErrorsRetainRequestCommand(t *testing.T) {
	for _, tc := range []struct {
		command uint16
		name    string
	}{
		{0, "negotiate"}, {1, "session setup"}, {2, "logoff"},
		{3, "tree connect"}, {4, "tree disconnect"}, {5, "create"},
		{6, "close"}, {8, "read"}, {9, "write"}, {11, "ioctl"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := connectionWithResponse(tc.command, 9, StatusAccessDenied, []byte{9, 0, 0, 0, 0, 0, 0, 0})
			_, err := c.exchange(tc.command, 9, nil)
			var status *NTStatusError
			if !errors.As(err, &status) || status.Status != StatusAccessDenied || status.Command != tc.command {
				t.Fatalf("status lost request command %q: %v", tc.name, err)
			}
			if err.Error() != "request: SMB status 0xc0000022" {
				t.Fatalf("command metadata changed the diagnostic: %v", err)
			}
		})
	}
}

func TestConnectionFailuresDistinguishNegotiationFromAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command uint16
		invoke  func(*Connection) error
	}{
		{"negotiate", 0, (*Connection).negotiate},
		{"session setup", SessionSetupCommand, (*Connection).authenticate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := connectionWithResponse(tc.command, 0, StatusAccountDisabled, []byte{9, 0, 0, 0, 0, 0, 0, 0})
			c.authenticated = false
			err := tc.invoke(c)
			var status *NTStatusError
			if !errors.As(err, &status) || status.Command != tc.command || status.Status != StatusAccountDisabled {
				t.Fatalf("connection failure lost its protocol phase: %v", err)
			}
			if c.messageID != 1 {
				t.Fatal("failed connection phase sent an additional request")
			}
		})
	}
}

func TestNegotiateSelectsCipherAndIgnoresUnknownContexts(t *testing.T) {
	type context struct {
		kind uint16
		data []byte
	}
	preauth := context{1, []byte{1, 0, 0, 0, 1, 0}} // One SHA-512 hash, no salt.
	for _, tt := range []struct {
		name      string
		contexts  []context
		encrypted bool
		valid     bool
	}{
		{"no_encryption_context", []context{preauth}, false, true},
		{"cipher_none", []context{preauth, {2, []byte{1, 0, 0, 0}}}, false, true},
		{"aes128_gcm", []context{preauth, {2, []byte{1, 0, 2, 0}}}, true, true},
		{"unoffered_cipher", []context{preauth, {2, []byte{1, 0, 1, 0}}}, false, false},
		{"empty_cipher_list", []context{preauth, {2, []byte{0, 0}}}, false, false},
		{"missing_cipher", []context{preauth, {2, []byte{1, 0}}}, false, false},
		{"multiple_ciphers", []context{preauth, {2, []byte{2, 0, 2, 0, 0, 0}}}, false, false},
		{"repeated_unknown", []context{preauth, {0xffff, []byte{1}}, {0xffff, []byte{2}}}, false, true},
		{"unknown_before_preauth", []context{{0xffff, nil}, preauth}, false, true},
		{"missing_preauth", []context{{0xffff, nil}}, false, false},
		{"duplicate_preauth", []context{preauth, preauth}, false, false},
		{"duplicate_cipher", []context{preauth, {2, []byte{1, 0, 2, 0}}, {2, []byte{1, 0, 2, 0}}}, false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// Encode an independent SMB3.1.1 response with 64 KiB limits.
			body := make([]byte, 64)
			binary.LittleEndian.PutUint16(body, 65)
			binary.LittleEndian.PutUint16(body[2:], 1)
			binary.LittleEndian.PutUint16(body[4:], 0x311)
			binary.LittleEndian.PutUint16(body[6:], uint16(len(tt.contexts)))
			for _, offset := range []int{28, 32, 36} {
				binary.LittleEndian.PutUint32(body[offset:], 65536)
			}
			binary.LittleEndian.PutUint32(body[60:], 128)
			for _, ctx := range tt.contexts {
				for len(body)%8 != 0 {
					body = append(body, 0)
				}
				body = binary.LittleEndian.AppendUint16(body, ctx.kind)
				body = binary.LittleEndian.AppendUint16(body, uint16(len(ctx.data)))
				body = append(body, 0, 0, 0, 0)
				body = append(body, ctx.data...)
			}
			_, wire := connectionWithResponse(0, 0, 0, body)
			conn := &Connection{wire: wire, credits: 1}
			err := conn.negotiate()
			if (err == nil) != tt.valid {
				t.Fatalf("negotiation err=%v, want valid=%t", err, tt.valid)
			}
			if tt.valid && (conn.dialect != 0x311 || conn.encryptionAvailable != tt.encrypted) {
				t.Fatalf("negotiation selected dialect=%#x, encryption=%t", conn.dialect, conn.encryptionAvailable)
			}
		})
	}
}

// This transport supplies a server packet without sharing the client's frame
// encoder. Its close state makes protocol-failure shutdown observable.
type responseConn struct {
	*bytes.Reader
	closed     bool
	writes     int
	closeCalls int
}

func (c *responseConn) Write(p []byte) (int, error) {
	if c.closed {
		return 0, net.ErrClosed
	}
	c.writes++
	return len(p), nil
}
func (c *responseConn) Close() error {
	c.closed = true
	c.closeCalls++
	return nil
}
func (c *responseConn) LocalAddr() net.Addr              { return nil }
func (c *responseConn) RemoteAddr() net.Addr             { return nil }
func (c *responseConn) SetDeadline(time.Time) error      { return nil }
func (c *responseConn) SetReadDeadline(time.Time) error  { return nil }
func (c *responseConn) SetWriteDeadline(time.Time) error { return nil }

func connectionWithResponse(command uint16, treeID, status uint32, body []byte) (*Connection, *responseConn) {
	packet := make([]byte, 4+64+len(body))
	binary.BigEndian.PutUint32(packet, uint32(len(packet)-4))
	header := packet[4:]
	copy(header, "\xfeSMB")
	binary.LittleEndian.PutUint16(header[4:], 64)
	binary.LittleEndian.PutUint32(header[8:], status)
	binary.LittleEndian.PutUint16(header[12:], command)
	binary.LittleEndian.PutUint16(header[14:], 1)
	binary.LittleEndian.PutUint32(header[16:], 1)
	binary.LittleEndian.PutUint32(header[36:], treeID)
	binary.LittleEndian.PutUint64(header[40:], 33)
	copy(header[64:], body)
	wire := &responseConn{Reader: bytes.NewReader(packet)}
	return &Connection{
		wire: wire, credits: 1, dialect: 0x210, sessionID: 33,
		authenticated: true, sessionFlags: 1, trees: map[string]*tree{"share": {id: 9, kind: 1}},
	}, wire
}

func TestCleanupResponsesRejectMalformedBodiesAndCloseTransport(t *testing.T) {
	for _, operation := range []struct {
		name    string
		command uint16
		treeID  uint32
		call    func(*Connection) error
	}{
		{"logoff", 2, 0, (*Connection).Logoff},
		{"tree_disconnect", 4, 9, func(c *Connection) error { return c.TreeDisconnect("share") }},
	} {
		for _, response := range []struct {
			name string
			body []byte
			good bool
		}{
			{"valid", []byte{4, 0, 0, 0}, true},
			{"header_only", nil, false},
			{"truncated", []byte{4, 0}, false},
			{"wrong_structure", []byte{9, 0, 0, 0}, false},
		} {
			t.Run(operation.name+"/"+response.name, func(t *testing.T) {
				c, wire := connectionWithResponse(operation.command, operation.treeID, 0, response.body)
				err := operation.call(c)
				wantClosed := !response.good || operation.command == 2
				if (err == nil) != response.good || wire.closed != wantClosed {
					t.Fatalf("cleanup result err=%v, closed=%v, valid=%v", err, wire.closed, response.good)
				}
			})
		}
	}
}

func TestDisconnectedHandlesCannotUseRecycledTreeIDs(t *testing.T) {
	for _, failDisconnect := range []bool{false, true} {
		body, status := []byte{4, 0, 0, 0}, uint32(0)
		if failDisconnect {
			body, status = []byte{9, 0, 0, 0, 0, 0, 0, 0}, StatusAccessDenied
		}
		c, wire := connectionWithResponse(4, 9, status, body)
		c.maxRead, c.maxWrite = 65536, 65536
		oldTree := &tree{id: 9, kind: 2}
		c.trees = map[string]*tree{"IPC$": oldTree}
		pipe := &File{c: c, tree: oldTree, pipe: true}
		err := c.TreeDisconnect("IPC$")
		if (err != nil) != failDisconnect {
			t.Fatalf("disconnect err=%v, want failure=%t", err, failDisconnect)
		}
		if !failDisconnect {
			// The server may reuse a disconnected TreeId for a different share.
			// That must not revive the previous pipe's read/write capability.
			body = make([]byte, 16)
			body[0], body[2] = 16, 1 // A disk share now uses the old pipe's ID.
			_, reply := connectionWithResponse(3, 9, 0, body)
			frame := make([]byte, reply.Len())
			_, _ = reply.Read(frame)
			binary.LittleEndian.PutUint64(frame[4+24:], c.messageID)
			wire.Reset(frame)
			if err := c.TreeConnect("disk"); err != nil {
				t.Fatal(err)
			}
			if c.trees["disk"].id != oldTree.id || c.trees["disk"] == oldTree {
				t.Fatal("fixture did not create a new tree instance with the recycled ID")
			}
		}
		writes := wire.writes
		if err := pipe.Write([]byte{1}); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("disconnected pipe write: %v", err)
		}
		if _, err := pipe.Read(1); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("disconnected pipe read: %v", err)
		}
		if err := pipe.Close(); err != nil {
			t.Fatalf("invalidated handle cleanup failed: %v", err)
		}
		if wire.writes != writes || wire.closed {
			t.Fatalf("stale handle touched another tree: writes=%d, want %d; closed=%t", wire.writes, writes, wire.closed)
		}
	}
}

func TestConnectionTerminationInvalidatesSessionAndHandles(t *testing.T) {
	for _, mode := range []string{"close", "logoff", "logoff_error", "logoff_canceled"} {
		t.Run(mode, func(t *testing.T) {
			body, status := []byte{4, 0, 0, 0}, uint32(0)
			if mode == "logoff_error" {
				body, status = []byte{9, 0, 0, 0, 0, 0, 0, 0}, StatusAccessDenied
			}
			c, wire := connectionWithResponse(2, 0, status, body)
			c.maxRead, c.maxWrite = 65536, 65536
			c.trees["share"].kind = 2
			pipe := &File{c: c, tree: c.trees["share"], pipe: true}
			if mode == "logoff_canceled" {
				c.opts.BeforeIO = func() error { return context.Canceled }
			}
			if mode == "close" {
				c.Close()
			} else {
				err := c.Logoff()
				switch mode {
				case "logoff":
					if err != nil {
						t.Fatal(err)
					}
				case "logoff_error":
					var status *NTStatusError
					if !errors.As(err, &status) || status.Status != StatusAccessDenied {
						t.Fatalf("logoff lost the server failure: %v", err)
					}
				case "logoff_canceled":
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("logoff lost cancellation: %v", err)
					}
				}
			}
			writes := wire.writes
			if err := pipe.Write([]byte{1}); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("closed session pipe write: %v", err)
			}
			if _, err := pipe.Read(1); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("closed session pipe read: %v", err)
			}
			if err := pipe.Close(); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("closed transport cleanup lost its diagnostic: %v", err)
			}
			if err := c.TreeConnect("new-share"); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("terminated session reused: %v", err)
			}
			if _, known := c.TreeMaximalAccess("share"); known || c.AuthResult() != AuthResultUnverified {
				t.Fatal("closed session still exposed active authorization state")
			}
			if err := c.Logoff(); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("repeated logoff lost closed-transport diagnostic: %v", err)
			}
			c.Close()
			if wire.writes != writes || wire.closeCalls != 1 {
				t.Fatalf("termination repeated I/O: writes=%d, want %d; closes=%d", wire.writes, writes, wire.closeCalls)
			}
		})
	}
	// An uninitialized connection has no transport or authorization to release.
	c := new(Connection)
	c.Close()
	c.Close()
}

func TestTreeConnectRejectsInvalidTreeMetadata(t *testing.T) {
	for _, tt := range []struct {
		name   string
		treeID uint32
		kind   byte
		good   bool
	}{
		{"disk", 10, 1, true},
		{"zero_tree", 0, 1, true},
		{"pipe", 10, 2, true},
		{"printer", 10, 3, true},
		{"zero_type", 10, 0, false},
		{"unknown_type", 10, 4, false},
		{"reserved_tree", 0xffffffff, 1, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			body := make([]byte, 16)
			body[0], body[2] = 16, tt.kind
			c, wire := connectionWithResponse(3, tt.treeID, 0, body)
			err := c.TreeConnect("new-share")
			_, connected := c.trees["new-share"]
			if (err == nil) != tt.good || connected != tt.good || wire.closed == tt.good {
				t.Fatalf("tree result err=%v, connected=%v, closed=%v, valid=%v", err, connected, wire.closed, tt.good)
			}
		})
	}
}

func TestTreeConnectRequiresReturnedTreeIdentifier(t *testing.T) {
	for _, status := range []uint32{0, StatusAccessDenied} {
		body := make([]byte, 16)
		body[0], body[2] = 16, 1
		if status != 0 {
			body = []byte{9, 0, 0, 0, 0, 0, 0, 0}
		}
		c, wire := connectionWithResponse(3, 10, status, body)
		frame := make([]byte, wire.Len())
		_, _ = wire.Read(frame)
		binary.LittleEndian.PutUint32(frame[4+16:], 3) // SERVER_TO_REDIR | ASYNC_COMMAND
		// These bytes are an AsyncId, even though its high half could be
		// mistaken for a valid TreeId in a synchronous header.
		binary.LittleEndian.PutUint64(frame[4+32:], uint64(10)<<32|1)
		wire.Reset(frame)
		err := c.TreeConnect("new-share")
		if err == nil {
			t.Fatal("accepted a tree connection without a returned TreeId")
		}
		if _, connected := c.trees["new-share"]; connected {
			t.Fatal("interpreted AsyncId bytes as a tree identifier")
		}
		var statusError *NTStatusError
		if status == 0 {
			if errors.As(err, &statusError) || !wire.closed {
				t.Fatalf("missing tree identifier was not a fatal protocol error: %v", err)
			}
		} else if !errors.As(err, &statusError) || statusError.Status != status || wire.closed {
			t.Fatalf("valid asynchronous denial was not preserved: %v", err)
		}
	}
}

func TestAsyncOpenRetainsRequestedTree(t *testing.T) {
	body := make([]byte, 88)
	binary.LittleEndian.PutUint16(body, 89)
	binary.LittleEndian.PutUint32(body[4:], 1) // FILE_OPENED
	c, wire := connectionWithResponse(5, 9, 0, body)
	frame := make([]byte, wire.Len())
	_, _ = wire.Read(frame)
	binary.LittleEndian.PutUint32(frame[4+16:], 3)
	binary.LittleEndian.PutUint64(frame[4+32:], uint64(10)<<32|1)
	pending := append([]byte(nil), frame[:4+64]...)
	pending = append(pending, 9, 0, 0, 0, 0, 0, 0, 0)
	binary.BigEndian.PutUint32(pending, uint32(len(pending)-4))
	binary.LittleEndian.PutUint32(pending[4+8:], statusPending)
	wire.Reset(append(pending, frame...))
	f, err := c.OpenRoot("share", FileReadAttributes, false)
	if err != nil {
		t.Fatal(err)
	}
	if f.tree != c.trees["share"] || f.tree.id != 9 || wire.closed {
		t.Fatal("asynchronous open replaced the requested tree with AsyncId bytes")
	}
}

func TestMalformedStatusResponsesDoNotBecomePermissionDenials(t *testing.T) {
	for _, tt := range []struct {
		name    string
		dialect uint16
		body    []byte
		valid   bool
	}{
		{"empty_error", 0x210, []byte{9, 0, 0, 0, 0, 0, 0, 0}, true},
		{"padding_after_empty_error", 0x210, []byte{9, 0, 0, 0, 0, 0, 0, 0, 0xff}, true},
		{"opaque_error_data", 0x210, []byte{9, 0, 0, 0, 4, 0, 0, 0, 1, 2, 3, 4}, true},
		{"error_context", 0x311, []byte{9, 0, 1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, true},
		{"header_only", 0x210, nil, false},
		{"truncated_structure", 0x210, []byte{9, 0}, false},
		{"wrong_structure", 0x210, []byte{4, 0, 0, 0, 0, 0, 0, 0}, false},
		{"truncated_error_data", 0x210, []byte{9, 0, 0, 0, 1, 0, 0, 0}, false},
		{"error_length_overflow", 0x210, []byte{9, 0, 0, 0, 255, 255, 255, 255}, false},
		{"unexpected_context", 0x210, []byte{9, 0, 1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
		{"missing_context", 0x311, []byte{9, 0, 1, 0, 0, 0, 0, 0}, false},
		{"truncated_context", 0x311, []byte{9, 0, 1, 0, 8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0}, false},
		{"missing_second_context", 0x311, []byte{9, 0, 2, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, wire := connectionWithResponse(5, 9, StatusAccessDenied, tt.body)
			c.dialect = tt.dialect
			_, err := c.exchange(5, 9, nil)
			var status *NTStatusError
			if errors.As(err, &status) != tt.valid || wire.closed == tt.valid {
				t.Fatalf("status result: err=%v, closed=%v, valid=%v", err, wire.closed, tt.valid)
			}
			if tt.valid && status.Status != StatusAccessDenied {
				t.Fatalf("lost authenticated status code: %#x", status.Status)
			}
		})
	}
}

func TestAuthenticationRejectsReservedSessionIdentifiers(t *testing.T) {
	for _, sessionID := range []uint64{0, ^uint64(0)} {
		c, wire := connectionWithResponse(1, 0, statusMoreProcessing, []byte{9, 0, 0, 0, 0, 0, 0, 0})
		frame := make([]byte, wire.Len())
		_, _ = wire.Read(frame)
		binary.LittleEndian.PutUint64(frame[4+40:], sessionID)
		wire.Reset(frame)
		c.authenticated, c.sessionID = false, 0
		err := c.authenticate()
		if err == nil || !strings.Contains(err.Error(), "session identifier") || c.messageID != 1 {
			t.Fatalf("session %#x: err=%v, authentication requests=%d", sessionID, err, c.messageID)
		}
	}
}

func TestAuthenticationHonorsInitialSPNEGOState(t *testing.T) {
	for _, tc := range []struct {
		name       string
		state      int
		wantWrites int
		errText    string
	}{
		{"completed", 0, 1, "completed SPNEGO"},
		{"rejected", 2, 1, "rejected SPNEGO"},
		{"incomplete", 1, 2, ""},
		{"request_mic", 3, 2, ""},
		{"omitted", -1, 2, ""},
		{"raw_ntlm", -2, 2, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			challenge := ntlmTestChallenge(ntlmOffer, true)
			token := challenge
			if tc.state != -2 {
				var state []byte
				if tc.state != -1 {
					state = der(0xa0, []byte{10, 1, byte(tc.state)})
				}
				token = der(0xa1, der(0x30, state, der(0xa2, der(4, challenge))))
			}
			body := make([]byte, 8+len(token))
			binary.LittleEndian.PutUint16(body, 9)
			binary.LittleEndian.PutUint16(body[4:], 72)
			binary.LittleEndian.PutUint16(body[6:], uint16(len(token)))
			copy(body[8:], token)
			c, wire := connectionWithResponse(SessionSetupCommand, 0, statusMoreProcessing, body)
			c.authenticated, c.sessionID, c.sessionFlags = false, 0, 0
			c.opts.Username, c.opts.Password, c.opts.Domain, c.opts.Host = "User", "Password", "Domain", "server"
			err := c.authenticate()
			// Continuation cases consume the challenge and stop at EOF while
			// waiting for the final response. Terminal states must stop first.
			if err == nil || wire.writes != tc.wantWrites || !strings.Contains(err.Error(), tc.errText) {
				t.Fatalf("authentication error=%v, requests=%d, want %d", err, wire.writes, tc.wantWrites)
			}
			if tc.wantWrites == 1 && (len(c.key) != 0 || len(c.signingKey) != 0 || c.authenticated) {
				t.Fatal("terminal SPNEGO state produced an authentication key or session")
			}
		})
	}
}

type authenticationTestConn struct {
	responseConn
	reply func([]byte) []byte
}

func (c *authenticationTestConn) Write(p []byte) (int, error) {
	n, err := c.responseConn.Write(p)
	if err == nil {
		c.Reset(c.reply(p[4:]))
	}
	return n, err
}

func TestAuthenticationRequiresRequestedServerMIC(t *testing.T) {
	for _, tc := range []struct {
		name         string
		initialState byte
		mic          string
		sessionFlags uint16
		wantIdentity int
	}{
		{"optional_absent", 1, "absent", 0, AuthResultUser},
		{"required_absent", 3, "absent", 0, AuthResultUnverified},
		{"required_empty_token", 3, "empty_token", 0, AuthResultUnverified},
		{"required_valid", 3, "valid", 0, AuthResultUser},
		{"required_tampered", 3, "tampered", 0, AuthResultUnverified},
		{"guest_absent", 3, "absent", 1, AuthResultGuest},
		{"anonymous_absent", 3, "absent", 2, AuthResultAnonymous},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Without NTLM key exchange, the exported session key is the
			// HMAC of the response proof under the published NTOWFv2 key.
			challenge := ntlmTestChallenge(ntlmOffer&^ntlmKeyExch, true)
			firstToken := der(0xa1, der(0x30, der(0xa0, []byte{10, 1, tc.initialState}), der(0xa2, der(4, challenge))))
			wire := &authenticationTestConn{responseConn: responseConn{Reader: bytes.NewReader(nil)}}
			wire.reply = func(request []byte) []byte {
				token, status, flags := firstToken, statusMoreProcessing, uint16(0)
				var key []byte
				if wire.writes == 2 {
					status, flags = 0, tc.sessionFlags
					start := bytes.Index(request, []byte("NTLMSSP\x00"))
					if start < 0 || len(request)-start < 64 {
						t.Fatal("authentication request omitted the NTLM response")
					}
					auth := request[start:]
					offset := int(binary.LittleEndian.Uint32(auth[24:]))
					if offset < 64 || offset > len(auth)-16 || binary.LittleEndian.Uint32(auth[60:])&ntlmKeyExch != 0 {
						t.Fatal("authentication request has invalid NTLM response fields")
					}
					h := hmac.New(md5.New, cryptoHex(t, "0c868a403bfd7a93a3001ef22ef02e3f"))
					h.Write(auth[offset : offset+16])
					key = h.Sum(nil)
					var micField []byte
					if tc.mic == "valid" || tc.mic == "tampered" {
						// Independent server-to-client NTLM signature with
						// sequence zero; key exchange was disabled above.
						signingKey := md5.Sum(append(append([]byte(nil), key...), "session key to server-to-client signing key magic constant\x00"...))
						h = hmac.New(md5.New, signingKey[:])
						h.Write([]byte{0, 0, 0, 0})
						h.Write(cryptoHex(t, "300c060a2b06010401823702020a"))
						mic := make([]byte, 16)
						mic[0] = 1
						copy(mic[4:12], h.Sum(nil)[:8])
						if tc.mic == "tampered" {
							mic[4] ^= 1
						}
						micField = der(0xa3, der(4, mic))
					}
					token = der(0xa1, der(0x30, der(0xa0, []byte{10, 1, 0}), micField))
					if tc.mic == "empty_token" {
						token = nil
					}
				}
				response := make([]byte, 72+len(token))
				copy(response, "\xfeSMB")
				binary.LittleEndian.PutUint16(response[4:], 64)
				binary.LittleEndian.PutUint32(response[8:], status)
				binary.LittleEndian.PutUint16(response[12:], SessionSetupCommand)
				binary.LittleEndian.PutUint16(response[14:], 1)
				binary.LittleEndian.PutUint32(response[16:], 1)
				copy(response[24:32], request[24:32])
				binary.LittleEndian.PutUint64(response[40:], 33)
				binary.LittleEndian.PutUint16(response[64:], 9)
				binary.LittleEndian.PutUint16(response[66:], flags)
				binary.LittleEndian.PutUint16(response[68:], 72)
				binary.LittleEndian.PutUint16(response[70:], uint16(len(token)))
				copy(response[72:], token)
				if key != nil && flags == 0 {
					binary.LittleEndian.PutUint32(response[16:], 9)
					h := hmac.New(sha256.New, key)
					h.Write(response)
					copy(response[48:64], h.Sum(nil)[:16])
				}
				return negotiateTestFrame(response)
			}
			c := &Connection{wire: wire, dialect: 0x210, credits: 1,
				opts: Options{Username: "User", Password: "Password", Domain: "Domain", Host: "server"}}
			err := c.authenticate()
			if (err == nil) != (tc.wantIdentity != AuthResultUnverified) || c.AuthResult() != tc.wantIdentity || wire.writes != 2 {
				t.Fatalf("authentication error=%v, identity=%d, requests=%d", err, c.AuthResult(), wire.writes)
			}
			if tc.wantIdentity == AuthResultUnverified && !strings.Contains(err.Error(), "mechanism-list MIC") {
				t.Fatalf("authentication failed before checking the server MIC: %v", err)
			}
		})
	}
}

func TestUTF16EncodingIncludesSupplementaryCharacters(t *testing.T) {
	want, _ := hex.DecodeString("4100e900346c3dd800de")
	if got := utf16Bytes("Aé水😀"); !bytes.Equal(got, want) {
		t.Fatalf("UTF-16LE = %x, want %x", got, want)
	}
	if got := utf16Bytes(""); len(got) != 0 {
		t.Fatalf("empty UTF-16LE string = %x", got)
	}
}

func TestDEREncodingLengthBoundariesAndOwnership(t *testing.T) {
	for _, tc := range []struct {
		length int
		header string
	}{
		{0, "0400"}, {1, "0401"}, {127, "047f"}, {128, "048180"},
		{255, "0481ff"}, {256, "04820100"}, {65000, "0482fde8"}, {65535, "0482ffff"},
	} {
		t.Run(tc.header, func(t *testing.T) {
			payload := bytes.Repeat([]byte{0x5a}, tc.length)
			got := der(4, payload[:len(payload)/2], nil, payload[len(payload)/2:])
			header := cryptoHex(t, tc.header)
			if len(got) != len(header)+len(payload) || !bytes.Equal(got[:len(header)], header) || !bytes.Equal(got[len(header):], payload) {
				t.Fatalf("incorrect DER header or payload for %d bytes", tc.length)
			}
			if len(payload) != 0 {
				payload[0] ^= 0xff
				if got[len(header)] != 0x5a {
					t.Fatal("encoded DER aliases the caller's input")
				}
			}
		})
	}
	if !bytes.Equal(der(4), []byte{4, 0}) {
		t.Fatal("incorrect DER encoding without payload parts")
	}
}

var benchmarkSPNEGOToken []byte

func BenchmarkSPNEGOEncoding(b *testing.B) {
	negotiate, auth, mic := ntlmNegotiate(), make([]byte, 512), make([]byte, 16)
	for _, tc := range []struct {
		name   string
		encode func() []byte
	}{
		{"initial", func() []byte { return spnegoInitial(negotiate) }},
		{"authenticate", func() []byte {
			return der(0xa1, der(0x30, der(0xa2, der(4, auth)), der(0xa3, der(4, mic))))
		}},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				benchmarkSPNEGOToken = tc.encode()
			}
		})
	}
}

func TestSPNEGOCompletionAndMechanismSelection(t *testing.T) {
	// Independently encoded NegTokenResp: accept_completed, NTLM mechanism.
	b, _ := hex.DecodeString("a1153013a0030a0100a10c060a2b06010401823702020a")
	state, token, mic, err := parseSPNEGOResponse(b)
	if err != nil || state != 0 || len(token) != 0 || len(mic) != 0 {
		t.Fatalf("completion=%d,%x,%x,%v", state, token, mic, err)
	}
	for _, invalid := range [][]byte{
		{0xa1, 0x80}, // Indefinite lengths are forbidden.
		{0xa1, 0x83, 0, 0, 0},
		append(append([]byte(nil), b...), 0),
		der(0xa1, der(0x30, der(0xa0, []byte{10, 1, 2}))), // rejected
		der(0xa1, der(0x30, der(0xa0, []byte{10, 1, 0}), der(0xa0, []byte{10, 1, 0}))),
		der(0xa1, der(0x30, der(0xa1, []byte{6, 1, 42}))), // unoffered mechanism
		der(0xa1, der(0x30, der(0xa3, der(4, []byte{1, 2})))),
	} {
		if _, _, _, err := parseSPNEGOResponse(invalid); err == nil {
			t.Errorf("accepted malformed SPNEGO response %x", invalid)
		}
	}
}

func TestSPNEGOIgnoresUnknownExtensions(t *testing.T) {
	token := append([]byte("NTLMSSP\x00"), 2, 0, 0, 0)
	mic := bytes.Repeat([]byte{0x93}, 16)
	stateField := []byte{0xa0, 3, 10, 1, 1}
	mechanismField := cryptoHex(t, "a10c060a2b06010401823702020a")
	for _, extension := range [][]byte{
		{0xa4, 0},                            // Empty opaque field.
		{0xa4, 3, 2, 1, 7},                   // Explicit [4] INTEGER.
		{0xbe, 3, 2, 1, 8},                   // Last single-byte tag number.
		{0xbf, 0x1f, 3, 2, 1, 9},             // High tag number [31].
		{0xbf, 0x81, 0, 3, 2, 1, 10},         // High tag number [128].
		{0xa4, 5, 0xa0, 3, 10, 1, 2},         // Nested reject is opaque.
		der(0xa4, der(4, make([]byte, 128))), // Long-form field length.
	} {
		// Known fields remain visible before and after extensions; their
		// token and MIC boundaries must not include opaque extension bytes.
		encoded := der(0xa1, der(0x30, extension, stateField, extension, mechanismField,
			der(0xa2, der(4, token)), extension, der(0xa3, der(4, mic)), extension))
		state, gotToken, gotMIC, err := parseSPNEGOResponse(encoded)
		if err != nil || state != 1 || !bytes.Equal(gotToken, token) || !bytes.Equal(gotMIC, mic) {
			t.Fatalf("extension %x changed known fields: state=%d token=%x MIC=%x err=%v", extension, state, gotToken, gotMIC, err)
		}
	}
}

func TestSPNEGOExtensionsCannotBypassFieldValidation(t *testing.T) {
	extension := []byte{0xa4, 3, 2, 1, 7}
	stateField := []byte{0xa0, 3, 10, 1, 1}
	for _, fields := range [][]byte{
		{0xa4},                 // Missing length.
		{0xa4, 4, 2, 1, 7},     // Truncated value.
		{0xa4, 0x80, 0, 0},     // Indefinite length.
		{0xa4, 0x82, 1},        // Truncated long-form length.
		{0xbf, 0x81},           // Truncated high tag number.
		{0xbf, 0x80, 4, 0},     // Nonminimal high tag number.
		{0xbf, 0, 3, 10, 1, 1}, // High-tag alias of known state.
		{0x80, 1, 1},           // Known state without explicit wrapper.
		{0x84, 0},              // Primitive context-specific field.
		{4, 0},                 // Universal field.
		{0x64, 0},              // Application field.
		{0xe4, 0},              // Private field.
		bytes.Join([][]byte{stateField, extension, stateField}, nil),
		bytes.Join([][]byte{extension, {0xa1, 3, 6, 1, 42}}, nil), // Unoffered mechanism.
		bytes.Join([][]byte{extension, {0xa3, 3, 4, 1, 0}}, nil),  // Invalid MIC size.
		bytes.Join([][]byte{extension, {0xa0, 3, 10, 1, 2}}, nil), // Rejected negotiation.
	} {
		if _, _, _, err := parseSPNEGOResponse(der(0xa1, der(0x30, fields))); err == nil {
			t.Fatalf("extension bypassed field validation: %x", fields)
		}
	}
}

func TestSPNEGOTokenBoundariesExcludeMechanismMIC(t *testing.T) {
	token := append([]byte("NTLMSSP\x00"), 2, 0, 0, 0)
	mic := bytes.Repeat([]byte{0x93}, 16)
	encoded := der(0xa1, der(0x30, der(0xa2, der(4, token)), der(0xa3, der(4, mic))))
	_, gotToken, gotMIC, err := parseSPNEGOResponse(encoded)
	if err != nil || !bytes.Equal(gotToken, token) || !bytes.Equal(gotMIC, mic) {
		t.Fatalf("token or MIC boundary lost: %x %x %v", gotToken, gotMIC, err)
	}
}

func TestBoundedSMBFieldRejectsOverflowAndHeaderOverlap(t *testing.T) {
	packet := make([]byte, 80)
	for _, field := range [][2]uint64{{63, 1}, {80, 1}, {79, 2}, {math.MaxUint64, 2}, {64, math.MaxUint64}} {
		if _, err := boundedField(packet, field[0], field[1], 64); err == nil {
			t.Errorf("accepted out-of-bounds field %v", field)
		}
	}
	if data, err := boundedField(packet, 64, 16, 64); err != nil || len(data) != 16 {
		t.Fatalf("valid field=%d %v", len(data), err)
	}
}

func FuzzSPNEGOResponse(f *testing.F) {
	f.Add([]byte{0xa1, 7, 0x30, 5, 0xa0, 3, 10, 1, 0})
	f.Add([]byte{0xa1, 0x82, 0xff, 0xff})
	f.Add(der(0xa1, der(0x30, []byte{0xa0, 3, 10, 1, 0, 0xbf, 0x81, 0, 3, 2, 1, 7})))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, token, mic, err := parseSPNEGOResponse(data)
		if err == nil && (len(token) > len(data) || len(mic) > len(data)) {
			t.Fatal("parsed fields exceed the message")
		}
	})
}

func TestRootRequestReadOnlyWireLayout(t *testing.T) {
	body, err := rootRequest(1, true)
	if err != nil {
		t.Fatal(err)
	}
	// Decode offsets independently of the production encoder. Offsets on
	// the wire are relative to the 64-byte SMB header.
	if len(body) != 88 || binary.LittleEndian.Uint16(body) != 57 ||
		binary.LittleEndian.Uint32(body[24:]) != 1 ||
		binary.LittleEndian.Uint32(body[32:]) != 7 ||
		binary.LittleEndian.Uint32(body[36:]) != 1 ||
		binary.LittleEndian.Uint32(body[40:]) != 1 {
		t.Fatalf("unexpected existing-root access request: %x", body)
	}
	if binary.LittleEndian.Uint16(body[44:]) != 120 || binary.LittleEndian.Uint16(body[46:]) != 0 ||
		binary.LittleEndian.Uint32(body[48:]) != 128 || binary.LittleEndian.Uint32(body[52:]) != 24 {
		t.Fatal("incorrect root name or context offsets")
	}
	ctx := body[64:]
	if string(ctx[16:20]) != "MxAc" || binary.LittleEndian.Uint32(ctx[:4]) != 0 || binary.LittleEndian.Uint32(ctx[12:]) != 0 {
		t.Fatal("expected one maximal-access context without a timestamp")
	}
}

func TestRootRequestRejectsWriteAndDeleteAccess(t *testing.T) {
	for _, access := range []uint32{0, 2, 4, 0x10000, 0x10000000, 0x001f01ff, 0x81} {
		if _, err := rootRequest(access, true); err == nil {
			t.Fatalf("accepted access %#x", access)
		}
	}
}
