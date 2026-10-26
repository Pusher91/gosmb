package smbwire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"testing"
)

type negotiateTestConn struct {
	responseConn
	sent bytes.Buffer
}

func (c *negotiateTestConn) Write(p []byte) (int, error) {
	n, err := c.responseConn.Write(p)
	if err == nil {
		_, _ = c.sent.Write(p[:n])
	}
	return n, err
}

func newNegotiateTestConnection(dialect uint16, encrypted bool) (*Connection, *negotiateTestConn) {
	wire := &negotiateTestConn{responseConn: responseConn{Reader: bytes.NewReader(nil)}}
	c := &Connection{
		wire: wire, dialect: dialect, sessionID: 33, credits: 1,
		authenticated: true, encryptionAvailable: encrypted, trees: make(map[string]*tree),
		key: bytes.Repeat([]byte{0x11}, 16), signingKey: bytes.Repeat([]byte{0x22}, 16),
		encryptionKey: bytes.Repeat([]byte{0x33}, 16), decryptionKey: bytes.Repeat([]byte{0x44}, 16),
	}
	c.clientNegotiateInfo = make([]byte, 34)
	binary.LittleEndian.PutUint32(c.clientNegotiateInfo, 0x40)
	copy(c.clientNegotiateInfo[4:20], "fixture-client!!")
	binary.LittleEndian.PutUint16(c.clientNegotiateInfo[20:], 3)
	binary.LittleEndian.PutUint16(c.clientNegotiateInfo[22:], 5)
	for i, value := range []uint16{0x202, 0x210, 0x300, 0x302, 0x311} {
		binary.LittleEndian.PutUint16(c.clientNegotiateInfo[24+2*i:], value)
	}
	binary.LittleEndian.PutUint32(c.serverNegotiateInfo[:], 0x40)
	copy(c.serverNegotiateInfo[4:20], "fixture-server!!")
	binary.LittleEndian.PutUint16(c.serverNegotiateInfo[20:], 3)
	binary.LittleEndian.PutUint16(c.serverNegotiateInfo[22:], dialect)
	return c, wire
}

// Encode control replies independently of the production request builder.
// Cryptographic helpers have separate known-answer and tampering tests.
func negotiateTestResponse(c *Connection, command uint16, id uint64, tree, status uint32) []byte {
	length := 136
	if command == 3 {
		length = 80
	}
	if status != 0 {
		length = 72
	}
	p := make([]byte, length)
	copy(p, "\xfeSMB")
	binary.LittleEndian.PutUint16(p[4:], 64)
	binary.LittleEndian.PutUint32(p[8:], status)
	binary.LittleEndian.PutUint16(p[12:], command)
	binary.LittleEndian.PutUint16(p[14:], 1)
	binary.LittleEndian.PutUint32(p[16:], 1)
	binary.LittleEndian.PutUint64(p[24:], id)
	binary.LittleEndian.PutUint32(p[36:], tree)
	binary.LittleEndian.PutUint64(p[40:], c.sessionID)
	if status != 0 {
		p[64] = 9
	} else if command == 3 {
		p[64], p[66] = 16, 1
	} else {
		p[64] = 49
		binary.LittleEndian.PutUint32(p[68:], 0x00140204)
		for i := 72; i < 88; i++ {
			p[i] = 0xff
		}
		binary.LittleEndian.PutUint32(p[88:], 112)
		binary.LittleEndian.PutUint32(p[96:], 112)
		binary.LittleEndian.PutUint32(p[100:], 24)
		copy(p[112:], c.serverNegotiateInfo[:])
	}
	return p
}

func negotiateTestProtect(t *testing.T, c *Connection, packet []byte) []byte {
	t.Helper()
	if c.sessionFlags&3 == 0 {
		binary.LittleEndian.PutUint32(packet[16:], 9)
		clear(packet[48:64])
		signature, err := signSMB(c.dialect, c.signingKey, packet)
		if err != nil {
			t.Fatal(err)
		}
		copy(packet[48:64], signature)
		if c.encryptionAvailable {
			packet, err = encryptSMB(c.dialect, c.decryptionKey, c.sessionID, packet)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	return packet
}

func negotiateTestFrame(packet []byte) []byte {
	frame := make([]byte, 4, 4+len(packet))
	binary.BigEndian.PutUint32(frame, uint32(len(packet)))
	return append(frame, packet...)
}

func TestNegotiateRetainsOriginalWireValues(t *testing.T) {
	for _, dialect := range []uint16{0x210, 0x300, 0x302} {
		t.Run(fmt.Sprintf("%04x", dialect), func(t *testing.T) {
			c, wire := newNegotiateTestConnection(dialect, false)
			c.authenticated, c.sessionID = false, 0
			packet := negotiateTestResponse(c, 0, 0, 0, 0)[:128]
			clear(packet[64:])
			binary.LittleEndian.PutUint16(packet[64:], 65)
			binary.LittleEndian.PutUint16(packet[66:], 3)
			binary.LittleEndian.PutUint16(packet[68:], dialect)
			copy(packet[72:88], "original-server!")
			binary.LittleEndian.PutUint32(packet[88:], 0x40)
			for _, offset := range []int{92, 96, 100} {
				binary.LittleEndian.PutUint32(packet[offset:], 65536)
			}
			wire.Reset(negotiateTestFrame(packet))
			if err := c.negotiate(); err != nil {
				t.Fatal(err)
			}
			offer := wire.sent.Bytes()[4:]
			wantClient := make([]byte, 34)
			copy(wantClient[:20], offer[72:92]) // Client capabilities and GUID.
			copy(wantClient[20:22], offer[68:70])
			copy(wantClient[22:24], offer[66:68])
			copy(wantClient[24:], offer[100:110])
			var wantServer [24]byte
			copy(wantServer[:4], packet[88:92])
			copy(wantServer[4:20], packet[72:88])
			copy(wantServer[20:24], packet[66:70])
			if !bytes.Equal(c.clientNegotiateInfo, wantClient) || c.serverNegotiateInfo != wantServer {
				t.Fatal("secure negotiation retained values different from the wire negotiation")
			}
		})
	}
}

func TestSecureNegotiateRequestAndReply(t *testing.T) {
	for _, dialect := range []uint16{0x202, 0x210, 0x300, 0x302} {
		for _, encrypted := range []bool{false, true} {
			if encrypted && dialect < 0x300 {
				continue
			}
			t.Run(fmt.Sprintf("%04x/encrypted=%t", dialect, encrypted), func(t *testing.T) {
				c, wire := newNegotiateTestConnection(dialect, encrypted)
				wire.Reset(negotiateTestFrame(negotiateTestProtect(t, c, negotiateTestResponse(c, 11, 0, 9, 0))))
				if err := c.validateNegotiateInfo(9); err != nil {
					t.Fatal(err)
				}
				frame := wire.sent.Bytes()
				if len(frame) < 4 || int(binary.BigEndian.Uint32(frame)) != len(frame)-4 {
					t.Fatal("validation did not send exactly one framed request")
				}
				p := frame[4:]
				if encrypted {
					var err error
					p, err = decryptSMB(dialect, c.encryptionKey, c.sessionID, p)
					if err != nil {
						t.Fatal(err)
					}
				}
				if len(p) != 154 || binary.LittleEndian.Uint16(p[12:]) != 11 || binary.LittleEndian.Uint32(p[16:]) != 8 ||
					binary.LittleEndian.Uint32(p[36:]) != 9 || binary.LittleEndian.Uint64(p[40:]) != 33 {
					t.Fatal("validation request has incorrect framing, command, signing, tree, or session")
				}
				var signature [16]byte
				copy(signature[:], p[48:64])
				clear(p[48:64])
				wantSignature, err := signSMB(dialect, c.signingKey, p)
				if err != nil || !bytes.Equal(signature[:], wantSignature) {
					t.Fatal("validation request lacks a valid signature")
				}
				if binary.LittleEndian.Uint16(p[64:]) != 57 || binary.LittleEndian.Uint32(p[68:]) != 0x00140204 ||
					!bytes.Equal(p[72:88], bytes.Repeat([]byte{0xff}, 16)) || binary.LittleEndian.Uint32(p[88:]) != 120 ||
					binary.LittleEndian.Uint32(p[92:]) != 34 || binary.LittleEndian.Uint32(p[96:]) != 0 ||
					binary.LittleEndian.Uint32(p[100:]) != 120 || binary.LittleEndian.Uint32(p[104:]) != 0 ||
					binary.LittleEndian.Uint32(p[108:]) != 24 || binary.LittleEndian.Uint32(p[112:]) != 1 ||
					!bytes.Equal(p[120:], c.clientNegotiateInfo) {
					t.Fatal("validation did not preserve the original offer or bounded, handle-free IOCTL layout")
				}
				writes := wire.writes
				if err := c.validateNegotiateInfo(10); err != nil || wire.writes != writes || !c.negotiationChecked || wire.closed {
					t.Fatalf("successful validation was repeated or closed the transport: %v", err)
				}
			})
		}
	}
}

func TestSecureNegotiateRejectsSignedMismatchAndMalformedResponse(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func([]byte) []byte
	}{
		{"capabilities", func(p []byte) []byte { p[112] ^= 1; return p }},
		{"GUID", func(p []byte) []byte { p[116] ^= 1; return p }},
		{"security_mode", func(p []byte) []byte { p[132] ^= 1; return p }},
		{"dialect", func(p []byte) []byte { p[134] ^= 1; return p }},
		{"structure_size", func(p []byte) []byte { p[64] = 48; return p }},
		{"control_code", func(p []byte) []byte { p[68] ^= 1; return p }},
		{"file_id", func(p []byte) []byte { p[80] = 0; return p }},
		{"unexpected_input", func(p []byte) []byte { p[92] = 1; return p }},
		{"short_output", func(p []byte) []byte { p[100] = 23; return p }},
		{"oversized_output", func(p []byte) []byte { p[100] = 25; return p }},
		{"header_overlap", func(p []byte) []byte { p[96] = 64; return p }},
		{"unaligned_output", func(p []byte) []byte { p[96] = 113; return append(p, 0) }},
		{"out_of_bounds_output", func(p []byte) []byte { binary.LittleEndian.PutUint32(p[96:], ^uint32(0)); return p }},
		{"truncated_body", func(p []byte) []byte { return p[:111] }},
		{"truncated_output", func(p []byte) []byte { return p[:135] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, wire := newNegotiateTestConnection(0x300, false)
			packet := tc.change(negotiateTestResponse(c, 11, 0, 9, 0))
			wire.Reset(negotiateTestFrame(negotiateTestProtect(t, c, packet)))
			err := c.validateNegotiateInfo(9)
			var status *NTStatusError
			if err == nil || !wire.closed || c.negotiationChecked || errors.As(err, &status) {
				t.Fatalf("invalid negotiation was not a terminal protocol failure: %v", err)
			}
		})
	}
}

func TestSecureNegotiateRequiresAuthenticatedResponses(t *testing.T) {
	for _, tc := range []string{"unsigned_success", "tampered_success", "unsigned_unsupported", "tampered_unsupported", "unencrypted_success"} {
		t.Run(tc, func(t *testing.T) {
			encrypted := tc == "unencrypted_success"
			dialect := uint16(0x210)
			if encrypted {
				dialect = 0x300
			}
			c, wire := newNegotiateTestConnection(dialect, encrypted)
			status := uint32(0)
			if tc == "unsigned_unsupported" || tc == "tampered_unsupported" {
				status = StatusNotSupported
			}
			packet := negotiateTestResponse(c, 11, 0, 9, status)
			if tc == "tampered_success" || tc == "tampered_unsupported" {
				packet = negotiateTestProtect(t, c, packet)
				packet[48] ^= 1
			}
			wire.Reset(negotiateTestFrame(packet))
			if err := c.validateNegotiateInfo(9); err == nil || !wire.closed || c.negotiationChecked {
				t.Fatalf("unprotected or modified response was accepted: %v", err)
			}
		})
	}
}

func TestSecureNegotiateUnsupportedPolicyAndAccessDenial(t *testing.T) {
	for _, dialect := range []uint16{0x202, 0x210, 0x300, 0x302} {
		for _, status := range []uint32{0xc00000bb, 0xc0000010, 0xc0000128, 0xc0000022, 0xc000000d} {
			t.Run(fmt.Sprintf("%04x/status=%08x", dialect, status), func(t *testing.T) {
				c, wire := newNegotiateTestConnection(dialect, false)
				wire.Reset(negotiateTestFrame(negotiateTestProtect(t, c, negotiateTestResponse(c, 11, 0, 9, status))))
				err := c.validateNegotiateInfo(9)
				unsupported := status == 0xc00000bb || status == 0xc0000010 || status == 0xc0000128
				allowed := dialect < 0x300 && unsupported
				var statusError *NTStatusError
				if (err == nil) != allowed || c.negotiationChecked != allowed || wire.closed == allowed || errors.As(err, &statusError) {
					t.Fatalf("validation status policy failed: allowed=%t, closed=%t, err=%v", allowed, wire.closed, err)
				}
			})
		}
	}
}

func TestTreeConnectValidatesNegotiationBeforeExposingTree(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		t.Run(fmt.Sprintf("mismatch=%t", mismatch), func(t *testing.T) {
			c, wire := newNegotiateTestConnection(0x210, false)
			frames := negotiateTestFrame(negotiateTestProtect(t, c, negotiateTestResponse(c, 3, 0, 9, 0)))
			validation := negotiateTestResponse(c, 11, 1, 9, 0)
			if mismatch {
				validation[134] ^= 1
			}
			frames = append(frames, negotiateTestFrame(negotiateTestProtect(t, c, validation))...)
			frames = append(frames, negotiateTestFrame(negotiateTestProtect(t, c, negotiateTestResponse(c, 3, 2, 10, 0)))...)
			wire.Reset(frames)
			err := c.TreeConnect("first")
			_, exposed := c.trees["first"]
			if (err != nil) != mismatch || exposed == mismatch || wire.closed != mismatch {
				t.Fatalf("tree exposure did not follow validation: exposed=%t, err=%v", exposed, err)
			}
			if !mismatch {
				if err := c.TreeConnect("second"); err != nil || wire.writes != 3 {
					t.Fatalf("validation was repeated on a second tree: writes=%d, err=%v", wire.writes, err)
				}
			}
		})
	}
}

func TestSecureNegotiateSkipsGuestAnonymousAndSMB311(t *testing.T) {
	for _, tc := range []struct {
		name    string
		dialect uint16
		flags   uint16
	}{{"guest", 0x300, 1}, {"anonymous", 0x300, 2}, {"SMB311", 0x311, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			c, wire := newNegotiateTestConnection(tc.dialect, false)
			c.sessionFlags = tc.flags
			wire.Reset(negotiateTestFrame(negotiateTestProtect(t, c, negotiateTestResponse(c, 3, 0, 9, 0))))
			if err := c.TreeConnect("share"); err != nil || wire.writes != 1 || wire.closed {
				t.Fatalf("unexpected validation request: writes=%d, err=%v", wire.writes, err)
			}
		})
	}
}

func TestSecureNegotiateTransportFailureRetainsCause(t *testing.T) {
	c, wire := newNegotiateTestConnection(0x210, false)
	if err := c.validateNegotiateInfo(9); !errors.Is(err, io.EOF) || !wire.closed || c.negotiationChecked {
		t.Fatalf("validation transport failure lost its cause or left the connection usable: %v", err)
	}
}
