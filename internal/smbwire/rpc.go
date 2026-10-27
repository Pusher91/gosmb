package smbwire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Connection-oriented DCE/RPC for MS-SRVS NetrShareEnum, opnum 15. NDR32
// layouts follow MS-SRVS 2.2.4.23, 2.2.4.24, 2.2.4.38 and 3.1.4.8.
// The pipe uses SMB session security; no separate RPC auth is negotiated.
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/c4a98e7b-d416-439c-97bd-4d9f52f8ba52
const (
	rpcFragmentSize = 4280
	rpcMaxStub      = 8 << 20
	rpcMaxFragments = 4096
	rpcMaxShares    = 16384
	rpcMaxShareText = 16 << 20
	rpcMaxPages     = 256
	ndrMaxString    = 65536
)

var ErrRPCDenied = errors.New("share enumeration denied")

// DCE syntax identifiers: UUID (first three fields little-endian), version.
var srvsvcSyntax = [20]byte{0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01, 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88, 3, 0, 0, 0}
var ndr32Syntax = [20]byte{0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, 2, 0, 0, 0}

type Share struct {
	Name, Comment string
	Type          uint32
}

type ShareEnumeration struct {
	Shares []Share
	// Complete records whether all pages arrived, even if cleanup later failed.
	Complete bool
	// Failure preserves a primary error observed while the connection was still
	// usable before cleanup. A later cleanup timeout must not replace that outcome.
	Failure error
}

type rpcPipe interface {
	Write([]byte) error
	Read(int) ([]byte, error)
	TransferLimits() (write, read int)
}

type rpcClient struct {
	pipe             rpcPipe
	pending          []byte
	callID           uint32
	maxSend, maxRecv int
}

func newRPCClient(pipe rpcPipe) *rpcClient {
	write, read := pipe.TransferLimits()
	return &rpcClient{pipe: pipe, maxSend: min(rpcFragmentSize, write), maxRecv: min(rpcFragmentSize, read)}
}

// EnumerateShares uses one existing session and never follows referrals.
// Writes carry RPC messages to the existing srvsvc pipe, never to disk files.
func (c *Connection) EnumerateShares() (result ShareEnumeration, err error) {
	if err = c.TreeConnect("IPC$"); err != nil {
		return result, fmt.Errorf("connect IPC$: %w", err)
	}
	var pipe *File
	defer func() {
		if err != nil && !c.closed.Load() {
			result.Failure = err
		}
		if pipe != nil {
			if cleanupErr := pipe.Close(); cleanupErr != nil && err == nil {
				err = fmt.Errorf("close enumeration pipe: %w", cleanupErr)
			}
		}
		if cleanupErr := c.TreeDisconnect("IPC$"); cleanupErr != nil && err == nil {
			err = fmt.Errorf("disconnect enumeration IPC$ share: %w", cleanupErr)
		}
	}()
	pipe, err = c.openPipe()
	if err != nil {
		return result, fmt.Errorf("open srvsvc pipe: %w", err)
	}
	rpc := newRPCClient(pipe)
	if err = rpc.bind(); err != nil {
		return result, fmt.Errorf("bind srvsvc RPC: %w", err)
	}
	result.Shares, err = enumeratePages(c.opts.Host, func(body []byte) ([]byte, error) { return rpc.call(15, body) })
	if err != nil {
		err = fmt.Errorf("NetrShareEnum: %w", err)
	}
	result.Complete = err == nil
	return result, err
}

func rpcHeader(kind, flags byte, length int, callID uint32) []byte {
	b := make([]byte, length)
	b[0], b[2], b[3], b[4] = 5, kind, flags, 0x10
	binary.LittleEndian.PutUint16(b[8:10], uint16(length))
	binary.LittleEndian.PutUint32(b[12:16], callID)
	return b
}

func (r *rpcClient) bind() error {
	if r.maxSend < 72 || r.maxRecv < 56 {
		return errors.New("SMB pipe transfer limits cannot carry an RPC bind")
	}
	r.callID++
	request := rpcHeader(11, 3, 72, r.callID)
	binary.LittleEndian.PutUint16(request[16:18], uint16(r.maxSend))
	binary.LittleEndian.PutUint16(request[18:20], uint16(r.maxRecv))
	request[24] = 1 // One presentation context: SRVS v3 using NDR32 v2.
	request[30] = 1 // One transfer syntax in context ID zero.
	copy(request[32:52], srvsvcSyntax[:])
	copy(request[52:72], ndr32Syntax[:])
	if err := r.pipe.Write(request); err != nil {
		return err
	}
	ack, err := r.readPDU()
	if err != nil {
		return err
	}
	if binary.LittleEndian.Uint32(ack[12:16]) != r.callID {
		return errors.New("RPC bind response has a different call ID")
	}
	if ack[2] == 3 {
		return rpcFault(ack)
	}
	if ack[2] != 12 || ack[3]&3 != 3 || len(ack) < 30 {
		return errors.New("RPC server did not return a complete bind acknowledgement")
	}
	serverSend := int(binary.LittleEndian.Uint16(ack[16:18]))
	serverReceive := int(binary.LittleEndian.Uint16(ack[18:20]))
	if serverSend <= 24 || serverReceive <= 24 {
		return errors.New("RPC server negotiated an invalid fragment size")
	}
	addressLength := int(binary.LittleEndian.Uint16(ack[24:26]))
	results := (26 + addressLength + 3) &^ 3
	if results > len(ack)-28 || ack[results] != 1 {
		return errors.New("invalid RPC bind result list")
	}
	result := ack[results+4 : results+28]
	if binary.LittleEndian.Uint16(result[:2]) != 0 || !bytes.Equal(result[4:24], ndr32Syntax[:]) {
		return errors.New("RPC server rejected SRVS version 3 with NDR32")
	}
	if results+28 != len(ack) {
		return errors.New("unexpected trailing RPC bind data")
	}
	r.maxSend = min(r.maxSend, serverReceive)
	r.maxRecv = min(r.maxRecv, serverSend)
	return nil
}

// Named-pipe reads may split or coalesce DCE fragments. Validate their common
// header before trusting lengths; keep unconsumed bytes for the next fragment.
func (r *rpcClient) readPDU() ([]byte, error) {
	for {
		if len(r.pending) >= 16 {
			h := r.pending[:16]
			if h[0] != 5 || h[1] != 0 || !bytes.Equal(h[4:8], []byte{0x10, 0, 0, 0}) || binary.LittleEndian.Uint16(h[10:12]) != 0 {
				return nil, errors.New("invalid or unsupported RPC common header")
			}
			length := int(binary.LittleEndian.Uint16(h[8:10]))
			if length < 16 || length > r.maxRecv {
				return nil, errors.New("RPC fragment length exceeds negotiated bounds")
			}
			if len(r.pending) >= length {
				// Future reads append after this fragment, never into its prefix.
				// Limit capacity so callers cannot append over the pending tail.
				pdu := r.pending[:length:length]
				r.pending = r.pending[length:]
				return pdu, nil
			}
		}
		part, err := r.pipe.Read(r.maxRecv)
		if err != nil {
			return nil, err
		}
		if len(part) == 0 {
			return nil, io.ErrNoProgress
		}
		if len(part) > r.maxRecv || len(r.pending)+len(part) > 2*r.maxRecv {
			return nil, errors.New("RPC pipe read exceeds negotiated bounds")
		}
		r.pending = append(r.pending, part...)
	}
}

func rpcFault(pdu []byte) error {
	if len(pdu) < 32 {
		return errors.New("truncated RPC fault")
	}
	// The status on the last fragment is authoritative (C706 12.6.2).
	// This client does not negotiate application-defined fault stubs, so it
	// accepts only a complete fault for its sole presentation context. Never
	// turn an incomplete or unrelated fault into an access-denied result.
	if pdu[3]&3 != 3 || binary.LittleEndian.Uint16(pdu[20:22]) != 0 {
		return errors.New("invalid or incomplete RPC fault")
	}
	status := binary.LittleEndian.Uint32(pdu[24:28])
	if status == 5 {
		return ErrRPCDenied
	}
	return fmt.Errorf("RPC server returned fault status 0x%08x", status)
}

func (r *rpcClient) call(opnum uint16, stub []byte) ([]byte, error) {
	if len(stub) > rpcMaxStub || r.maxSend <= 24 {
		return nil, errors.New("RPC request exceeds supported bounds")
	}
	payloadSize := r.maxSend - 24
	if len(stub) > rpcMaxFragments*payloadSize {
		return nil, errors.New("RPC request exceeds the fragment safety limit")
	}
	r.callID++
	for offset := 0; ; {
		count := min(len(stub)-offset, payloadSize)
		flags := byte(0)
		if offset == 0 {
			flags |= 1
		}
		if offset+count == len(stub) {
			flags |= 2
		}
		pdu := rpcHeader(0, flags, 24+count, r.callID)
		binary.LittleEndian.PutUint32(pdu[16:20], uint32(len(stub)-offset))
		binary.LittleEndian.PutUint16(pdu[22:24], opnum)
		copy(pdu[24:], stub[offset:offset+count])
		if err := r.pipe.Write(pdu); err != nil {
			return nil, err
		}
		offset += count
		if flags&2 != 0 {
			break
		}
	}
	var response []byte
	for fragment := 0; fragment < rpcMaxFragments; fragment++ {
		pdu, err := r.readPDU()
		if err != nil {
			return nil, err
		}
		if binary.LittleEndian.Uint32(pdu[12:16]) != r.callID {
			return nil, errors.New("RPC response has a different call ID")
		}
		if pdu[2] == 3 {
			return nil, rpcFault(pdu)
		}
		if pdu[2] != 2 || len(pdu) < 24 || binary.LittleEndian.Uint16(pdu[20:22]) != 0 || (pdu[3]&1 != 0) != (fragment == 0) {
			return nil, errors.New("invalid RPC response fragment sequence")
		}
		if binary.LittleEndian.Uint32(pdu[16:20]) > rpcMaxStub || len(response)+len(pdu)-24 > rpcMaxStub {
			return nil, errors.New("RPC response exceeds the safety limit")
		}
		response = append(response, pdu[24:]...)
		if pdu[3]&2 != 0 {
			return response, nil
		}
		if len(pdu) == 24 {
			return nil, errors.New("RPC response fragment made no progress")
		}
	}
	return nil, errors.New("RPC response exceeded the fragment safety limit")
}

// enumeratePages preserves successful pages if a later call fails. The caps
// bound hostile allocation counts and non-progressing resume cursors.
func enumeratePages(host string, call func([]byte) ([]byte, error)) ([]Share, error) {
	shares := []Share{}
	body, err := encodeShareRequest(host, 0)
	if err != nil {
		return shares, err
	}
	seen, seenResume := make(map[string]bool), make(map[uint32]bool)
	retainedText := 0
	for page := 0; page < rpcMaxPages; page++ {
		response, err := call(body)
		if err != nil {
			return shares, err
		}
		decoded, err := decodeSharePage(response)
		if err != nil {
			return shares, fmt.Errorf("decode share list: %w", err)
		}
		if decoded.status != 0 && decoded.status != 234 {
			if decoded.status == 5 {
				return shares, ErrRPCDenied
			}
			return shares, fmt.Errorf("NetShareEnum returned Windows status %d", decoded.status)
		}
		for _, share := range decoded.shares {
			key := shareNameKey(share.Name)
			if seen[key] {
				continue
			}
			if len(shares) >= rpcMaxShares {
				return shares, errors.New("share enumeration exceeded 16384-share safety limit")
			}
			textSize := len(share.Name) + len(share.Comment)
			if textSize > rpcMaxShareText-retainedText {
				return shares, errors.New("share enumeration exceeded the 16 MiB text safety limit")
			}
			retainedText += textSize
			seen[key] = true
			shares = append(shares, share)
		}
		if decoded.status == 0 {
			return shares, nil
		}
		if !decoded.hasResume || decoded.resume == 0 || seenResume[decoded.resume] {
			return shares, errors.New("server returned a non-progressing share enumeration cursor")
		}
		seenResume[decoded.resume] = true
		// The host and level are unchanged; only the resume handle advances.
		binary.LittleEndian.PutUint32(body[len(body)-4:], decoded.resume)
	}
	return shares, errors.New("share enumeration exceeded 256-page safety limit")
}

// MS-SRVS 3.1.4.34 leaves case-insensitive comparison implementation-specific.
// Fold only ASCII case so local Unicode mappings cannot hide distinct names
// reported by the server. Exact non-ASCII repeats still share a key.
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/073d1b6c-d608-4778-ac5f-6240eda83b34
func shareNameKey(name string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, name)
}

func encodeShareRequest(host string, resume uint32) ([]byte, error) {
	if !utf8.ValidString(host) || strings.ContainsRune(host, 0) || len(host) > 1024 {
		return nil, errors.New("invalid RPC server name")
	}
	serverName := utf16Bytes(`\\` + strings.TrimPrefix(host, `\\`) + "\x00")
	// Reserve the 16-byte string header, aligned name, and 32-byte arguments.
	b := make([]byte, 0, 16+((len(serverName)+3)&^3)+32)
	put := func(value uint32) { b = binary.LittleEndian.AppendUint32(b, value) }
	put(0x20000) // Unique server-name pointer, followed by its string referent.
	put(uint32(len(serverName) / 2))
	put(0)
	put(uint32(len(serverName) / 2))
	b = append(b, serverName...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	put(1)       // InfoStruct.Level.
	put(1)       // Non-encapsulated union discriminator.
	put(0x20004) // SHARE_INFO_1_CONTAINER pointer.
	put(0)       // EntriesRead.
	put(0)       // NULL input array.
	put(65536)   // Bounded preferred page length.
	put(0x20008) // ResumeHandle pointer, including on the first call.
	put(resume)
	return b, nil
}

type decodedSharePage struct {
	shares    []Share
	resume    uint32
	hasResume bool
	status    uint32
}

type ndrShareReader struct {
	data []byte
	off  int
	err  error
}

func (r *ndrShareReader) fail() {
	if r.err == nil {
		r.err = errors.New("invalid NDR32 share response")
	}
}

func (r *ndrShareReader) u32() uint32 {
	r.off = (r.off + 3) &^ 3
	if r.err != nil || r.off > len(r.data)-4 {
		r.fail()
		return 0
	}
	value := binary.LittleEndian.Uint32(r.data[r.off : r.off+4])
	r.off += 4
	return value
}

func (r *ndrShareReader) text() string {
	maximum, offset, count := r.u32(), r.u32(), r.u32()
	if r.err != nil || maximum > ndrMaxString || offset > maximum || count == 0 || count > maximum-offset || uint64(count)*2 > uint64(len(r.data)-r.off) {
		r.fail()
		return ""
	}
	end := r.off + int(count)*2
	if binary.LittleEndian.Uint16(r.data[end-2:end]) != 0 {
		r.fail()
		return ""
	}
	data := r.data[r.off : end-2]
	r.off = end
	// Validate and size the UTF-8 result before allocating it. Decoding through
	// temporary UTF-16 and rune slices multiplies memory use for large pages.
	size := 0
	for i := 0; i < len(data); i += 2 {
		unit := binary.LittleEndian.Uint16(data[i : i+2])
		if unit == 0 || unit >= 0xdc00 && unit <= 0xdfff {
			r.fail()
			return ""
		}
		switch {
		case unit < 0x80:
			size++
		case unit < 0x800:
			size += 2
		case unit >= 0xd800 && unit <= 0xdbff:
			i += 2
			if i >= len(data) {
				r.fail()
				return ""
			}
			low := binary.LittleEndian.Uint16(data[i : i+2])
			if low < 0xdc00 || low > 0xdfff {
				r.fail()
				return ""
			}
			size += 4
		default:
			size += 3
		}
	}
	var text strings.Builder
	text.Grow(size)
	for i := 0; i < len(data); i += 2 {
		unit := rune(binary.LittleEndian.Uint16(data[i : i+2]))
		if unit >= 0xd800 && unit <= 0xdbff {
			i += 2
			unit = utf16.DecodeRune(unit, rune(binary.LittleEndian.Uint16(data[i:i+2])))
		}
		text.WriteRune(unit)
	}
	return text.String()
}

func decodeSharePage(data []byte) (decodedSharePage, error) {
	var result decodedSharePage
	if len(data) > rpcMaxStub {
		return result, errors.New("share response exceeds the safety limit")
	}
	r := ndrShareReader{data: data}
	level, discriminator := r.u32(), r.u32()
	if r.err != nil || level != 1 || discriminator != 1 {
		return result, errors.New("server returned invalid share information level")
	}
	if r.u32() != 0 {
		count, array := r.u32(), r.u32()
		if r.err != nil || count > rpcMaxShares || array == 0 && count != 0 {
			return result, errors.New("invalid share array count")
		}
		if array != 0 {
			conformance := r.u32()
			if r.err != nil || conformance != count || uint64(count)*12 > uint64(len(data)-r.off) {
				return result, errors.New("invalid share array conformance")
			}
			type refs struct{ name, comment uint32 }
			pointers := make([]refs, int(count))
			result.shares = make([]Share, int(count))
			for i := range result.shares {
				pointers[i].name = r.u32()
				result.shares[i].Type = r.u32()
				pointers[i].comment = r.u32()
			}
			for i := range result.shares {
				if pointers[i].name != 0 {
					result.shares[i].Name = r.text()
				}
				if pointers[i].comment != 0 {
					result.shares[i].Comment = r.text()
				}
			}
		}
	}
	_ = r.u32() // TotalEntries is advisory; never allocate from it.
	result.hasResume = r.u32() != 0
	if result.hasResume {
		result.resume = r.u32()
	}
	result.status = r.u32()
	if r.err != nil || r.off != len(data) {
		return decodedSharePage{}, errors.New("invalid or trailing NDR32 share response data")
	}
	return result, nil
}
