package smbwire

import (
	"bytes"
	"context"
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

func TestUTF16EncodingIncludesSupplementaryCharacters(t *testing.T) {
	want, _ := hex.DecodeString("4100e900346c3dd800de")
	if got := utf16Bytes("Aé水😀"); !bytes.Equal(got, want) {
		t.Fatalf("UTF-16LE = %x, want %x", got, want)
	}
	if got := utf16Bytes(""); len(got) != 0 {
		t.Fatalf("empty UTF-16LE string = %x", got)
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
		der(0xa1, der(0x30, der(0xa4, nil))),
	} {
		if _, _, _, err := parseSPNEGOResponse(invalid); err == nil {
			t.Errorf("accepted malformed SPNEGO response %x", invalid)
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
