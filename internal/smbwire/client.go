// Package smbwire implements the bounded SMB2/3 client subset used by gosmb.
// It opens existing share roots and the srvsvc pipe; it has no disk mutation API.
// Wire layouts follow Microsoft's MS-SMB2 and MS-SPNG specifications.
package smbwire

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync/atomic"
	"unicode/utf16"
)

const (
	StatusAccessDenied       uint32 = 0xc0000022
	StatusInvalidParameter   uint32 = 0xc000000d
	StatusNotSupported       uint32 = 0xc00000bb
	StatusLogonFailure       uint32 = 0xc000006d
	StatusAccountRestriction uint32 = 0xc000006e
	StatusInvalidLogonHours  uint32 = 0xc000006f
	StatusInvalidWorkstation uint32 = 0xc0000070
	StatusPasswordExpired    uint32 = 0xc0000071
	StatusAccountDisabled    uint32 = 0xc0000072
	StatusAccountExpired     uint32 = 0xc0000193
	StatusPasswordMustChange uint32 = 0xc0000224
	StatusAccountLockedOut   uint32 = 0xc0000234
	FileListDirectory        uint32 = 1
	FileReadAttributes       uint32 = 0x80
	AuthResultUser                  = 0
	AuthResultGuest                 = 1
	AuthResultAnonymous             = 2
	AuthResultUnverified            = 3
	// SessionSetupCommand identifies authentication status responses.
	SessionSetupCommand  uint16 = 1
	maxFrame                    = 16 << 20
	statusPending        uint32 = 0x103
	statusMoreProcessing uint32 = 0xc0000016
	statusBufferOverflow uint32 = 0x80000005
)

type NTStatusError struct {
	Status uint32
	// Command identifies the request which received this status. The same
	// status code can mean different things before or after authentication.
	Command uint16
}

func (e *NTStatusError) Error() string { return fmt.Sprintf("request: SMB status 0x%08x", e.Status) }

type Options struct {
	Host                       string
	Username, Password, Domain string
	Guest                      bool
	// Dial opens the one caller-selected, bounded connection. It is invoked
	// exactly once; authentication never retries or selects another endpoint.
	Dial func() (net.Conn, error)
	// BeforeIO arms the caller's operation/host deadline. Cancellation closes
	// this same socket; there are no background receivers or implicit retries.
	BeforeIO func() error
}

type tree struct {
	id, flags, access uint32
	kind              byte
	closed            bool
}
type Connection struct {
	maxRead, maxWrite                             uint32
	wire                                          net.Conn
	opts                                          Options
	messageID, sessionID                          uint64
	credits                                       uint32
	dialect                                       uint16
	preauth                                       [64]byte
	clientNegotiateInfo                           []byte
	serverNegotiateInfo                           [24]byte
	negotiationChecked                            bool
	key, signingKey, encryptionKey, decryptionKey []byte
	sessionFlags                                  uint16
	authenticated, encryptionAvailable            bool
	closed                                        atomic.Bool
	trees                                         map[string]*tree
}

func NewConnection(opts Options) (*Connection, error) {
	if opts.Dial == nil {
		return nil, errors.New("SMB connection requires a bounded dialer")
	}
	wire, err := opts.Dial()
	if err != nil {
		return nil, err
	}
	c := &Connection{wire: wire, opts: opts, credits: 1, trees: make(map[string]*tree)}
	if err = c.negotiate(); err == nil {
		err = c.authenticate()
	}
	// Credentials are only needed during the single initial exchange.
	c.opts.Password, c.opts.Username, c.opts.Domain = "", "", ""
	c.opts.Dial = nil
	if err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func (c *Connection) Close() {
	// Closing the transport invalidates every tree/handle without mutating
	// their maps while an interrupted exchange is returning on another goroutine.
	if c.closed.CompareAndSwap(false, true) && c.wire != nil {
		_ = c.wire.Close()
	}
}
func (c *Connection) protocolError(message string) error {
	c.Close()
	return errors.New(message)
}

// AuthResult exposes the completed session's identity without exposing keys.
// A successful NTLM exchange may still establish Guest or anonymous access.
func (c *Connection) AuthResult() int {
	if c.closed.Load() || !c.authenticated {
		return AuthResultUnverified
	}
	switch c.sessionFlags {
	case 1:
		return AuthResultGuest
	case 2:
		return AuthResultAnonymous
	case 0, 4:
		if len(c.key) == 16 && len(c.signingKey) == 16 {
			return AuthResultUser
		}
	}
	return AuthResultUnverified
}
func (c *Connection) Logoff() error {
	if c.closed.Load() {
		return net.ErrClosed
	}
	// This client owns exactly one session. A logoff attempt is terminal even
	// if its response is lost or rejected, so its keys cannot authorize reuse.
	defer c.Close()
	r, err := c.exchange(2, 0, []byte{4, 0, 0, 0})
	if err != nil {
		return err
	}
	if len(r) < 68 || binary.LittleEndian.Uint16(r[64:]) != 4 {
		return c.protocolError("invalid SMB logoff response")
	}
	return nil
}

func (c *Connection) hashPacket(packet []byte) {
	h := sha512.New()
	h.Write(c.preauth[:])
	h.Write(packet)
	copy(c.preauth[:], h.Sum(nil))
}

func (c *Connection) exchange(command uint16, treeID uint32, body []byte) (result []byte, err error) {
	if c.closed.Load() {
		return nil, net.ErrClosed
	}
	defer func() {
		// A protocol, integrity, or transport error poisons the stream. Normal
		// authenticated NT status errors permit the documented read-only fallbacks.
		var status *NTStatusError
		if err != nil && !errors.As(err, &status) {
			c.Close()
		}
	}()
	if c.opts.BeforeIO != nil {
		if err := c.opts.BeforeIO(); err != nil {
			return nil, err
		}
	}
	if c.credits == 0 {
		return nil, errors.New("server exhausted SMB credits")
	}
	packet := make([]byte, 64+len(body))
	copy(packet, "\xfeSMB")
	binary.LittleEndian.PutUint16(packet[4:], 64)
	if c.dialect != 0x202 {
		binary.LittleEndian.PutUint16(packet[6:], 1)
	}
	binary.LittleEndian.PutUint16(packet[12:], command)
	binary.LittleEndian.PutUint16(packet[14:], 32)
	binary.LittleEndian.PutUint64(packet[24:], c.messageID)
	binary.LittleEndian.PutUint32(packet[36:], treeID)
	binary.LittleEndian.PutUint64(packet[40:], c.sessionID)
	copy(packet[64:], body)
	id := c.messageID
	c.messageID++
	c.credits--
	if command == 0 || (command == SessionSetupCommand && c.dialect == 0x311) {
		c.hashPacket(packet)
	}
	if command == SessionSetupCommand && len(c.key) != 0 {
		var err error
		c.signingKey, c.encryptionKey, c.decryptionKey, err = deriveKeys(c.dialect, c.key, c.preauth[:])
		if err != nil {
			return nil, err
		}
	}
	secure := c.authenticated && c.sessionFlags&3 == 0
	encrypted := secure && c.encryptionAvailable
	// Secure negotiation requires an explicit signature even when the
	// request is also protected by the session's encryption policy.
	if secure && (!encrypted || command == smb2IOCTL) {
		binary.LittleEndian.PutUint32(packet[16:], 8)
		sig, err := signSMB(c.dialect, c.signingKey, packet)
		if err != nil {
			return nil, err
		}
		copy(packet[48:64], sig)
	}
	if encrypted {
		var err error
		packet, err = encryptSMB(c.dialect, c.encryptionKey, c.sessionID, packet)
		if err != nil {
			return nil, err
		}
	}
	if err := writeFrame(c.wire, packet); err != nil {
		return nil, err
	}
	var asyncID uint64
	for pending := 0; pending < 64; pending++ {
		response, err := readFrame(c.wire)
		if err != nil {
			return nil, err
		}
		sealed := len(response) >= 4 && string(response[:4]) == "\xfdSMB"
		if sealed {
			if !secure || !c.encryptionAvailable {
				return nil, errors.New("unexpected encrypted SMB response")
			}
			response, err = decryptSMB(c.dialect, c.decryptionKey, c.sessionID, response)
			if err != nil {
				return nil, err
			}
		} else if encrypted {
			return nil, errors.New("unencrypted response to encrypted SMB request")
		}
		if len(response) < 64 || string(response[:4]) != "\xfeSMB" || binary.LittleEndian.Uint16(response[4:]) != 64 {
			return nil, errors.New("invalid SMB response header")
		}
		flags := binary.LittleEndian.Uint32(response[16:])
		if flags&1 == 0 || binary.LittleEndian.Uint32(response[20:]) != 0 || binary.LittleEndian.Uint16(response[12:]) != command || binary.LittleEndian.Uint64(response[24:]) != id {
			return nil, errors.New("mismatched SMB response")
		}
		if command != 0 && command != SessionSetupCommand && binary.LittleEndian.Uint64(response[40:]) != c.sessionID {
			return nil, errors.New("mismatched SMB session")
		}
		status := binary.LittleEndian.Uint32(response[8:])
		if flags&2 != 0 {
			got := binary.LittleEndian.Uint64(response[32:])
			if got == 0 {
				return nil, errors.New("empty SMB asynchronous identifier")
			}
			if asyncID != 0 && got != asyncID {
				return nil, errors.New("mismatched SMB asynchronous response")
			}
			asyncID = got
		} else if asyncID != 0 {
			return nil, errors.New("SMB asynchronous response lost its identifier")
		} else if command != 0 && command != SessionSetupCommand && command != 3 && binary.LittleEndian.Uint32(response[36:]) != treeID {
			return nil, errors.New("mismatched SMB tree")
		}
		// Interim pending responses are explicitly unsigned in MS-SMB2. They
		// cannot extend the socket deadline and are bounded in count.
		if status != statusPending && secure && !sealed {
			if err := c.verify(response); err != nil {
				return nil, err
			}
		}
		failed := status != 0 && !(command == SessionSetupCommand && status == statusMoreProcessing) && !(command == 8 && status == statusBufferOverflow)
		if failed && !validErrorResponse(response, c.dialect) {
			return nil, errors.New("invalid SMB error response")
		}
		c.credits += uint32(binary.LittleEndian.Uint16(response[14:]))
		if c.credits > 65535 {
			c.credits = 65535
		}
		if status == statusPending {
			if flags&2 == 0 || binary.LittleEndian.Uint32(response[68:]) != 0 {
				return nil, errors.New("invalid pending SMB response")
			}
			continue
		}
		if command == 0 || (command == SessionSetupCommand && c.dialect == 0x311 && status == statusMoreProcessing) {
			c.hashPacket(response)
		}
		if failed {
			return nil, &NTStatusError{Status: status, Command: command}
		}
		return response, nil
	}
	return nil, errors.New("too many pending SMB responses")
}

// Error statuses must carry a valid SMB2 ERROR body before they can trigger
// permission fallbacks. Extended error contexts are opaque to this client, but
// their advertised lengths must still fit the enclosing response.
func validErrorResponse(packet []byte, dialect uint16) bool {
	if len(packet) < 72 || binary.LittleEndian.Uint16(packet[64:]) != 9 {
		return false
	}
	count := int(packet[66])
	size := uint64(binary.LittleEndian.Uint32(packet[68:]))
	if size > uint64(len(packet)-72) || (dialect != 0x311 && count != 0) {
		return false
	}
	data := packet[72 : 72+int(size)]
	for i, offset := 0, 0; i < count; i++ {
		if offset > len(data)-8 {
			return false
		}
		n := uint64(binary.LittleEndian.Uint32(data[offset:]))
		if n > uint64(len(data)-offset-8) {
			return false
		}
		offset = (offset + 8 + int(n) + 7) &^ 7
	}
	return true
}

func (c *Connection) verify(packet []byte) error {
	if binary.LittleEndian.Uint32(packet[16:])&8 == 0 {
		return errors.New("server returned an unsigned user-session response")
	}
	var saved [16]byte
	copy(saved[:], packet[48:64])
	clear(packet[48:64])
	sig, err := signSMB(c.dialect, c.signingKey, packet)
	copy(packet[48:64], saved[:])
	if err != nil {
		return err
	}
	if !hmac.Equal(sig, saved[:]) {
		return errors.New("invalid SMB response signature")
	}
	return nil
}

func writeFrame(w io.Writer, packet []byte) error {
	if len(packet) > maxFrame || len(packet) > 0xffffff {
		return errors.New("SMB frame exceeds size limit")
	}
	frame := make([]byte, len(packet)+4)
	binary.BigEndian.PutUint32(frame, uint32(len(packet)))
	copy(frame[4:], packet)
	for len(frame) > 0 {
		n, err := w.Write(frame)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		frame = frame[n:]
	}
	return nil
}
func readFrame(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(header[:])
	if header[0] != 0 || n < 64 || n > maxFrame {
		return nil, errors.New("invalid SMB transport length")
	}
	packet := make([]byte, int(n))
	_, err := io.ReadFull(r, packet)
	return packet, err
}

func (c *Connection) negotiate() error {
	dialects := [...]uint16{0x202, 0x210, 0x300, 0x302, 0x311}
	body := make([]byte, (36+2*len(dialects)+7)&^7)
	binary.LittleEndian.PutUint16(body, 36)
	binary.LittleEndian.PutUint16(body[2:], uint16(len(dialects)))
	// Request signing and verify every user response. A server-reported Guest
	// session is a separately reported, deliberately unsigned identity.
	binary.LittleEndian.PutUint16(body[4:], 3)
	binary.LittleEndian.PutUint32(body[8:], 0x40)
	if _, err := rand.Read(body[12:28]); err != nil {
		return err
	}
	binary.LittleEndian.PutUint32(body[28:], uint32(64+len(body)))
	binary.LittleEndian.PutUint16(body[32:], 3)
	for i, d := range dialects {
		binary.LittleEndian.PutUint16(body[36+i*2:], d)
	}
	// Retain an independent copy of the exact offer for secure negotiation.
	// Its layout is VALIDATE_NEGOTIATE_INFO, not the NEGOTIATE wire body.
	c.clientNegotiateInfo = make([]byte, 24+2*len(dialects))
	copy(c.clientNegotiateInfo[:20], body[8:28])
	copy(c.clientNegotiateInfo[20:22], body[4:6])
	copy(c.clientNegotiateInfo[22:24], body[2:4])
	copy(c.clientNegotiateInfo[24:], body[36:36+2*len(dialects)])
	preauth := make([]byte, 38)
	binary.LittleEndian.PutUint16(preauth, 1)
	binary.LittleEndian.PutUint16(preauth[2:], 32)
	binary.LittleEndian.PutUint16(preauth[4:], 1)
	if _, err := rand.Read(preauth[6:]); err != nil {
		return err
	}
	for _, ctx := range []struct {
		kind uint16
		data []byte
	}{{1, preauth}, {2, []byte{1, 0, 2, 0}}, {8, []byte{1, 0, 1, 0}}} {
		for len(body)%8 != 0 {
			body = append(body, 0)
		}
		h := make([]byte, 8)
		binary.LittleEndian.PutUint16(h, ctx.kind)
		binary.LittleEndian.PutUint16(h[2:], uint16(len(ctx.data)))
		body = append(body, h...)
		body = append(body, ctx.data...)
	}
	r, err := c.exchange(0, 0, body)
	if err != nil {
		return err
	}
	if len(r) < 128 || binary.LittleEndian.Uint16(r[64:]) != 65 {
		return errors.New("invalid SMB negotiate response")
	}
	c.dialect = binary.LittleEndian.Uint16(r[68:])
	if !slices.Contains(dialects[:], c.dialect) {
		return errors.New("server selected an unoffered SMB dialect")
	}
	if binary.LittleEndian.Uint16(r[66:])&1 == 0 {
		return errors.New("server does not support SMB signing")
	}
	copy(c.serverNegotiateInfo[:4], r[88:92])
	copy(c.serverNegotiateInfo[4:20], r[72:88])
	copy(c.serverNegotiateInfo[20:24], r[66:70])
	if _, err = boundedField(r, uint64(binary.LittleEndian.Uint16(r[120:])), uint64(binary.LittleEndian.Uint16(r[122:])), 128); err != nil {
		return err
	}
	for _, off := range []int{92, 96, 100} {
		if binary.LittleEndian.Uint32(r[off:]) < 1024 {
			return errors.New("server SMB transfer limit is too small")
		}
	}
	c.maxRead = min(binary.LittleEndian.Uint32(r[96:]), 65536)
	c.maxWrite = min(binary.LittleEndian.Uint32(r[100:]), 65536)
	c.encryptionAvailable = c.dialect >= 0x300 && c.dialect < 0x311 && binary.LittleEndian.Uint32(r[88:])&0x40 != 0
	if c.dialect == 0x311 {
		count := int(binary.LittleEndian.Uint16(r[70:]))
		offset := uint64(binary.LittleEndian.Uint32(r[124:]))
		var seen [9]bool
		if count < 1 || count > 32 || offset < 128 || offset%8 != 0 {
			return errors.New("invalid SMB negotiate contexts")
		}
		for i := 0; i < count; i++ {
			h, err := boundedField(r, offset, 8, 128)
			if err != nil {
				return err
			}
			kind := binary.LittleEndian.Uint16(h)
			n := uint64(binary.LittleEndian.Uint16(h[2:]))
			data, err := boundedField(r, offset+8, n, 128)
			if err != nil {
				return err
			}
			// MS-SMB2 3.2.5.2 requires unknown contexts to be ignored, even
			// when repeated. Uniqueness applies to the defined capabilities.
			switch kind {
			case 1, 2, 3, 6, 7, 8:
				if seen[kind] {
					return errors.New("duplicate SMB negotiate context")
				}
				seen[kind] = true
			}
			switch kind {
			case 1:
				if len(data) < 6 || binary.LittleEndian.Uint16(data) != 1 || binary.LittleEndian.Uint16(data[4:]) != 1 || int(binary.LittleEndian.Uint16(data[2:])) != len(data)-6 {
					return errors.New("unsupported SMB preauthentication hash")
				}
			case 2:
				if len(data) != 4 || binary.LittleEndian.Uint16(data) != 1 {
					return errors.New("unsupported SMB encryption selection")
				}
				// One cipher with ID zero means encryption is unavailable.
				// An empty cipher list is not a valid server selection.
				switch binary.LittleEndian.Uint16(data[2:]) {
				case 0:
				case 2: // AES-128-GCM, the cipher offered by this client.
					c.encryptionAvailable = true
				default:
					return errors.New("unsupported SMB encryption selection")
				}
			case 8:
				if len(data) != 4 || binary.LittleEndian.Uint16(data) != 1 || binary.LittleEndian.Uint16(data[2:]) != 1 {
					return errors.New("unsupported SMB signing selection")
				}
			}
			offset = (offset + 8 + n + 7) &^ 7
		}
		if !seen[1] {
			return errors.New("missing SMB preauthentication context")
		}
	}
	return nil
}

func (c *Connection) authenticate() error {
	neg := ntlmNegotiate()
	first := spnegoInitial(neg)
	r, err := c.exchange(SessionSetupCommand, 0, sessionSetupBody(first))
	if err != nil {
		return err
	}
	if binary.LittleEndian.Uint32(r[8:]) != statusMoreProcessing {
		return errors.New("server completed authentication without an NTLM challenge")
	}
	if len(r) < 72 || binary.LittleEndian.Uint16(r[64:]) != 9 {
		return errors.New("invalid session setup response")
	}
	c.sessionID = binary.LittleEndian.Uint64(r[40:])
	if c.sessionID == 0 || c.sessionID == ^uint64(0) {
		return errors.New("server returned an invalid SMB session identifier")
	}
	blob, err := boundedField(r, uint64(binary.LittleEndian.Uint16(r[68:])), uint64(binary.LittleEndian.Uint16(r[70:])), 72)
	if err != nil {
		return err
	}
	initialState, challenge, _, err := parseSPNEGOResponse(blob)
	if err != nil {
		return err
	}
	// RFC 4178 4.2.2: accept-completed is terminal. A challenge cannot
	// request another NTLM token after SPNEGO has completed.
	if initialState == 0 {
		return errors.New("server completed SPNEGO authentication before NTLM authentication")
	}
	auth, key, err := ntlmAuthenticate(neg, challenge, c.opts.Username, c.opts.Password, c.opts.Domain, c.opts.Host, c.opts.Guest)
	if err != nil {
		return err
	}
	c.key = key
	mechList := ntlmMechList()
	mic, err := ntlmMechListMIC(auth, key, mechList)
	if err != nil {
		return err
	}
	token := der(0xa1, der(0x30, der(0xa2, der(4, auth)), der(0xa3, der(4, mic))))
	if len(token) > 65535 {
		return errors.New("NTLM authentication token exceeds SMB size limit")
	}
	r, err = c.exchange(SessionSetupCommand, 0, sessionSetupBody(token))
	if err != nil {
		return err
	}
	if len(r) < 72 || binary.LittleEndian.Uint16(r[64:]) != 9 {
		return errors.New("invalid final session setup response structure")
	}
	if binary.LittleEndian.Uint64(r[40:]) != c.sessionID {
		return errors.New("server changed the authentication session identifier")
	}
	if binary.LittleEndian.Uint32(r[8:]) != 0 {
		return fmt.Errorf("unexpected additional authentication exchange (status 0x%08x)", binary.LittleEndian.Uint32(r[8:]))
	}
	blob, err = boundedField(r, uint64(binary.LittleEndian.Uint16(r[68:])), uint64(binary.LittleEndian.Uint16(r[70:])), 72)
	if err != nil {
		return err
	}
	var serverMIC []byte
	if len(blob) != 0 {
		state, responseToken, mic, err := parseSPNEGOResponse(blob)
		if err != nil {
			return err
		}
		if (state != 0 && state != -1) || len(responseToken) != 0 {
			return errors.New("server did not complete SPNEGO authentication")
		}
		serverMIC = mic
	}
	c.sessionFlags = binary.LittleEndian.Uint16(r[66:])
	if c.sessionFlags != 0 && c.sessionFlags != 1 && c.sessionFlags != 2 && c.sessionFlags != 4 {
		return errors.New("server returned contradictory or unknown session flags")
	}
	if c.sessionFlags == 4 && c.dialect < 0x300 {
		return errors.New("server requested encryption with an SMB2 dialect")
	}
	if c.sessionFlags&3 != 0 {
		c.key = nil
		c.signingKey = nil
		c.encryptionAvailable = false
	} else {
		if err = c.verify(r); err != nil {
			return err
		}
		if c.sessionFlags&4 != 0 && !c.encryptionAvailable {
			return errors.New("server requires unavailable SMB encryption")
		}
		// RFC 4178 3.1 and 5(c)(I): request-mic requires the exchange in
		// both directions, including the acceptor's final mechanism-list MIC.
		if initialState == 3 && len(serverMIC) == 0 {
			return errors.New("server omitted the required SPNEGO mechanism-list MIC")
		}
		if len(serverMIC) != 0 {
			if err := ntlmVerifyMechListMIC(auth, key, mechList, serverMIC); err != nil {
				return err
			}
		}
	}
	c.authenticated = true
	return nil
}

func sessionSetupBody(token []byte) []byte {
	b := make([]byte, 24+len(token))
	binary.LittleEndian.PutUint16(b, 25)
	b[3] = 3
	binary.LittleEndian.PutUint16(b[12:], 88)
	binary.LittleEndian.PutUint16(b[14:], uint16(len(token)))
	copy(b[24:], token)
	return b
}

func utf16Bytes(value string) []byte {
	b := make([]byte, 0, len(value)*2)
	for _, r := range value {
		if r <= 0xffff {
			b = binary.LittleEndian.AppendUint16(b, uint16(r))
		} else {
			high, low := utf16.EncodeRune(r)
			b = binary.LittleEndian.AppendUint16(b, uint16(high))
			b = binary.LittleEndian.AppendUint16(b, uint16(low))
		}
	}
	return b
}
func boundedField(packet []byte, offset, length uint64, minimum uint64) ([]byte, error) {
	if length == 0 {
		return nil, nil
	}
	if offset < minimum || offset > uint64(len(packet)) || length > uint64(len(packet))-offset {
		return nil, errors.New("invalid SMB response field bounds")
	}
	return packet[int(offset):int(offset+length)], nil
}

func (c *Connection) TreeConnect(name string) error {
	if _, ok := c.trees[name]; ok {
		return errors.New("duplicate SMB tree connection")
	}
	if name == "" || strings.ContainsAny(name, "\\/\x00") {
		return errors.New("invalid SMB share name")
	}
	path := utf16Bytes("\\\\" + c.opts.Host + "\\" + name)
	if len(path) > 8192 {
		return errors.New("SMB share path too long")
	}
	b := make([]byte, 8+len(path))
	binary.LittleEndian.PutUint16(b, 9)
	binary.LittleEndian.PutUint16(b[4:], 72)
	binary.LittleEndian.PutUint16(b[6:], uint16(len(path)))
	copy(b[8:], path)
	r, err := c.exchange(3, 0, b)
	if err != nil {
		return err
	}
	if len(r) < 80 || binary.LittleEndian.Uint16(r[64:]) != 16 {
		return c.protocolError("invalid tree connect response")
	}
	// An ASYNC header replaces TreeId with AsyncId. Unlike operations on an
	// existing tree, TREE_CONNECT needs the reply's new tree identifier.
	if binary.LittleEndian.Uint32(r[16:])&2 != 0 {
		return c.protocolError("tree connect response has no tree identifier")
	}
	t := &tree{id: binary.LittleEndian.Uint32(r[36:]), kind: r[66], flags: binary.LittleEndian.Uint32(r[68:]), access: binary.LittleEndian.Uint32(r[76:])}
	if t.id == 0xffffffff || t.kind < 1 || t.kind > 3 {
		return c.protocolError("invalid SMB tree identifier or share type")
	}
	if t.flags&0x8000 != 0 && (!c.encryptionAvailable || c.sessionFlags&3 != 0) {
		return errors.New("share requires unavailable encryption")
	}
	if err := c.validateNegotiateInfo(t.id); err != nil {
		return err
	}
	c.trees[name] = t
	return nil
}
func (c *Connection) TreeMaximalAccess(name string) (uint32, bool) {
	t, ok := c.trees[name]
	if !ok || t == nil || t.closed || c.closed.Load() {
		return 0, false
	}
	return t.access, true
}
func (c *Connection) TreeDisconnect(name string) error {
	t, ok := c.trees[name]
	if !ok {
		return errors.New("unknown SMB tree")
	}
	delete(c.trees, name)
	t.closed = true
	r, err := c.exchange(4, t.id, []byte{4, 0, 0, 0})
	if err != nil {
		return err
	}
	if len(r) < 68 || binary.LittleEndian.Uint16(r[64:]) != 4 {
		return c.protocolError("invalid SMB tree disconnect response")
	}
	return nil
}

type File struct {
	c             *Connection
	tree          *tree
	id            [16]byte
	pipe, closed  bool
	Contexts      []byte
	MetadataError error
}

// rootRequest encodes only an existing directory-root open. A context changes
// the requested metadata, never the requested access or creation disposition.
func rootRequest(desired uint32, maximal bool) ([]byte, error) {
	if desired != FileListDirectory && desired != FileReadAttributes {
		return nil, errors.New("refusing non-read-only root access")
	}
	b := make([]byte, 64)
	binary.LittleEndian.PutUint16(b, 57)
	binary.LittleEndian.PutUint32(b[4:], 2)
	binary.LittleEndian.PutUint32(b[24:], desired)
	binary.LittleEndian.PutUint32(b[32:], 7)
	binary.LittleEndian.PutUint32(b[36:], 1)
	binary.LittleEndian.PutUint32(b[40:], 1)
	binary.LittleEndian.PutUint16(b[44:], 120)
	if maximal {
		binary.LittleEndian.PutUint32(b[48:], 128)
		binary.LittleEndian.PutUint32(b[52:], 24)
		ctx := make([]byte, 24)
		binary.LittleEndian.PutUint16(ctx[4:], 16)
		binary.LittleEndian.PutUint16(ctx[6:], 4)
		copy(ctx[16:], "MxAc")
		b = append(b, ctx...)
	}
	return b, nil
}
func (c *Connection) OpenRoot(share string, desired uint32, maximal bool) (*File, error) {
	t, ok := c.trees[share]
	if !ok || t.kind != 1 {
		return nil, errors.New("root open requires a connected disk share")
	}
	b, err := rootRequest(desired, maximal)
	if err != nil {
		return nil, err
	}
	return c.create(t, b, false)
}
func (c *Connection) openPipe() (*File, error) {
	t, ok := c.trees["IPC$"]
	if !ok || t.kind != 2 {
		return nil, errors.New("srvsvc requires a connected IPC$ share")
	}
	name := utf16Bytes("srvsvc")
	b := make([]byte, 56+len(name))
	binary.LittleEndian.PutUint16(b, 57)
	binary.LittleEndian.PutUint32(b[4:], 2)
	binary.LittleEndian.PutUint32(b[24:], 0x100003)
	binary.LittleEndian.PutUint32(b[32:], 7)
	binary.LittleEndian.PutUint32(b[36:], 1)
	binary.LittleEndian.PutUint16(b[44:], 120)
	binary.LittleEndian.PutUint16(b[46:], uint16(len(name)))
	copy(b[56:], name)
	return c.create(t, b, true)
}
func (c *Connection) create(t *tree, body []byte, pipe bool) (*File, error) {
	r, err := c.exchange(5, t.id, body)
	if err != nil {
		return nil, err
	}
	if len(r) < 152 {
		c.Close()
		return nil, errors.New("truncated open response")
	}
	f := &File{c: c, tree: t, pipe: pipe}
	copy(f.id[:], r[128:144])
	if binary.LittleEndian.Uint16(r[64:]) != 89 || binary.LittleEndian.Uint32(r[68:]) != 1 {
		return nil, c.protocolError("server returned an unexpected result for existing-object open")
	}
	off, n := uint64(binary.LittleEndian.Uint32(r[144:])), uint64(binary.LittleEndian.Uint32(r[148:]))
	f.Contexts, f.MetadataError = boundedField(r, off, n, 152)
	if n != 0 && off%8 != 0 {
		f.MetadataError = errors.New("unaligned SMB create context")
		f.Contexts = nil
	}
	return f, nil
}
func (f *File) Close() error {
	if f.closed || f.tree == nil || f.tree.closed {
		f.closed = true
		return nil
	}
	f.closed = true
	if f.c == nil || f.c.closed.Load() {
		return net.ErrClosed
	}
	b := make([]byte, 24)
	binary.LittleEndian.PutUint16(b, 24)
	copy(b[8:], f.id[:])
	r, err := f.c.exchange(6, f.tree.id, b)
	if err != nil {
		return err
	}
	if len(r) < 124 || binary.LittleEndian.Uint16(r[64:]) != 60 {
		return f.c.protocolError("invalid SMB close response")
	}
	return nil
}

func (f *File) isOpen() bool {
	return !f.closed && f.c != nil && !f.c.closed.Load() && f.tree != nil && !f.tree.closed
}

func (f *File) TransferLimits() (write, read int) { return int(f.c.maxWrite), int(f.c.maxRead) }

func (f *File) Write(data []byte) error {
	if !f.pipe {
		return errors.New("SMB writes are restricted to the existing srvsvc pipe")
	}
	if !f.isOpen() {
		return net.ErrClosed
	}
	if len(data) < 1 || len(data) > int(f.c.maxWrite) {
		return errors.New("invalid RPC pipe write size")
	}
	b := make([]byte, 48+len(data))
	binary.LittleEndian.PutUint16(b, 49)
	binary.LittleEndian.PutUint16(b[2:], 112)
	binary.LittleEndian.PutUint32(b[4:], uint32(len(data)))
	copy(b[16:], f.id[:])
	copy(b[48:], data)
	r, err := f.c.exchange(9, f.tree.id, b)
	if err != nil {
		return err
	}
	if len(r) < 80 || binary.LittleEndian.Uint16(r[64:]) != 17 || binary.LittleEndian.Uint32(r[68:]) != uint32(len(data)) {
		return f.c.protocolError("short or invalid RPC pipe write")
	}
	return nil
}
func (f *File) Read(maximum int) ([]byte, error) {
	if !f.pipe {
		return nil, errors.New("SMB reads are restricted to the existing srvsvc pipe")
	}
	if !f.isOpen() {
		return nil, net.ErrClosed
	}
	if maximum < 1 || maximum > 65536 {
		return nil, errors.New("invalid RPC pipe read size")
	}
	maximum = min(maximum, int(f.c.maxRead))
	b := make([]byte, 49)
	binary.LittleEndian.PutUint16(b, 49)
	binary.LittleEndian.PutUint32(b[4:], uint32(maximum))
	copy(b[16:], f.id[:])
	binary.LittleEndian.PutUint32(b[32:], 1)
	r, err := f.c.exchange(8, f.tree.id, b)
	if err != nil {
		return nil, err
	}
	if len(r) < 80 || binary.LittleEndian.Uint16(r[64:]) != 17 {
		return nil, f.c.protocolError("invalid RPC pipe read response")
	}
	n := uint64(binary.LittleEndian.Uint32(r[68:]))
	if n == 0 || n > uint64(maximum) {
		return nil, f.c.protocolError("invalid RPC pipe read length")
	}
	data, err := boundedField(r, uint64(r[66]), n, 80)
	if err != nil {
		f.c.Close()
	}
	return data, err
}

func der(tag byte, parts ...[]byte) []byte {
	n := 0
	for _, part := range parts {
		n += len(part)
	}
	b := make([]byte, 0, n+4)
	b = append(b, tag)
	if n < 128 {
		b = append(b, byte(n))
	} else if n < 256 {
		b = append(b, 0x81, byte(n))
	} else {
		b = append(b, 0x82, byte(n>>8), byte(n))
	}
	for _, part := range parts {
		b = append(b, part...)
	}
	return b
}
func spnegoInitial(token []byte) []byte {
	return der(0x60, []byte{6, 6, 0x2b, 6, 1, 5, 5, 2}, der(0xa0, der(0x30, der(0xa0, ntlmMechList()), der(0xa2, der(4, token)))))
}
func ntlmMechList() []byte { return der(0x30, []byte{6, 10, 0x2b, 6, 1, 4, 1, 0x82, 0x37, 2, 2, 10}) }

func derValue(data []byte, tag byte) (value, rest []byte, err error) {
	if len(data) < 2 || data[0] != tag {
		return nil, nil, errors.New("invalid SPNEGO field")
	}
	n, start := int(data[1]), 2
	if n&128 != 0 {
		count := n & 127
		if count < 1 || count > 2 || len(data) < 2+count {
			return nil, nil, errors.New("invalid SPNEGO length")
		}
		n = 0
		for _, v := range data[2 : 2+count] {
			n = n*256 + int(v)
		}
		start += count
	}
	if n > len(data)-start {
		return nil, nil, errors.New("truncated SPNEGO field")
	}
	return data[start : start+n], data[start+n:], nil
}

func parseSPNEGOResponse(blob []byte) (state int, token, mic []byte, err error) {
	state = -1
	if len(blob) >= 12 && string(blob[:8]) == "NTLMSSP\x00" {
		return state, blob, nil, nil
	}
	outer, rest, err := derValue(blob, 0xa1)
	if err != nil || len(rest) != 0 {
		return state, nil, nil, errors.New("invalid SPNEGO response envelope")
	}
	fields, rest, err := derValue(outer, 0x30)
	if err != nil || len(rest) != 0 {
		return state, nil, nil, errors.New("invalid SPNEGO response sequence")
	}
	var seen [4]bool
	for len(fields) > 0 {
		tag := fields[0]
		if tag < 0xa0 || tag > 0xa3 {
			// RFC 4178 6 requires unknown extension fields to be ignored.
			// RawValue bounds the complete explicit field, including high
			// tag numbers, without interpreting its opaque contents.
			var extension asn1.RawValue
			rest, e := asn1.Unmarshal(fields, &extension)
			if e != nil || extension.Class != asn1.ClassContextSpecific || !extension.IsCompound || extension.Tag <= 3 {
				return state, nil, nil, errors.New("invalid SPNEGO extension field")
			}
			fields = rest
			continue
		}
		if seen[tag-0xa0] {
			return state, nil, nil, errors.New("duplicate SPNEGO response field")
		}
		seen[tag-0xa0] = true
		var field []byte
		field, fields, err = derValue(fields, tag)
		if err != nil {
			return state, nil, nil, err
		}
		innerTag := byte(4)
		if tag == 0xa0 {
			innerTag = 10
		}
		if tag == 0xa1 {
			innerTag = 6
		}
		value, tail, e := derValue(field, innerTag)
		if e != nil || len(tail) != 0 {
			return state, nil, nil, errors.New("invalid SPNEGO response field value")
		}
		switch tag {
		case 0xa0:
			if len(value) != 1 || value[0] > 3 || value[0] == 2 {
				return state, nil, nil, errors.New("server rejected SPNEGO authentication")
			}
			state = int(value[0])
		case 0xa1:
			if !bytes.Equal(value, []byte{0x2b, 6, 1, 4, 1, 0x82, 0x37, 2, 2, 10}) {
				return state, nil, nil, errors.New("server selected an unoffered authentication mechanism")
			}
		case 0xa2:
			token = value
		case 0xa3:
			if len(value) != 16 {
				return state, nil, nil, errors.New("invalid NTLM mechanism-list MIC size")
			}
			mic = value
		}
	}
	return state, token, mic, nil
}
