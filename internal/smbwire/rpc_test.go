package smbwire

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"unicode/utf16"
)

// Fixture encoders intentionally do not call production RPC/NDR encoders.
func rpcFixturePage(shares []Share, status, resume uint32) []byte {
	var b []byte
	put := func(v uint32) {
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		b = binary.LittleEndian.AppendUint32(b, v)
	}
	text := func(s string) {
		u := append(utf16.Encode([]rune(s)), 0)
		put(uint32(len(u)))
		put(0)
		put(uint32(len(u)))
		for _, v := range u {
			b = binary.LittleEndian.AppendUint16(b, v)
		}
	}
	put(1)
	put(1)
	put(1)
	put(uint32(len(shares)))
	put(2)
	put(uint32(len(shares)))
	for i, s := range shares {
		put(uint32(10 + 2*i))
		put(s.Type)
		if s.Comment == "" {
			put(0)
		} else {
			put(uint32(11 + 2*i))
		}
	}
	for _, s := range shares {
		text(s.Name)
		if s.Comment != "" {
			text(s.Comment)
		}
	}
	put(uint32(len(shares)))
	put(3)
	put(resume)
	put(status)
	return b
}

func rpcFixturePDU(kind, flags byte, callID uint32, payload []byte) []byte {
	b := make([]byte, 24+len(payload))
	b[0], b[2], b[3], b[4] = 5, kind, flags, 0x10
	binary.LittleEndian.PutUint16(b[8:10], uint16(len(b)))
	binary.LittleEndian.PutUint32(b[12:16], callID)
	binary.LittleEndian.PutUint32(b[16:20], uint32(len(payload)))
	copy(b[24:], payload)
	return b
}

func rpcFixtureAck() []byte {
	b := make([]byte, 56)
	b[0], b[2], b[3], b[4], b[8] = 5, 12, 3, 0x10, 56
	b[12], b[16], b[18], b[28] = 1, 64, 64, 1
	syntax, _ := hex.DecodeString("045d888aeb1cc9119fe808002b10486002000000")
	copy(b[36:], syntax)
	return b
}

type rpcTestPipe struct{ reads, writes [][]byte }

func (p *rpcTestPipe) TransferLimits() (int, int) { return 4280, 4280 }

type rpcLimitedTestPipe struct {
	*rpcTestPipe
	writeLimit, readLimit int
}

func (p *rpcLimitedTestPipe) TransferLimits() (int, int) {
	return p.writeLimit, p.readLimit
}

func (p *rpcLimitedTestPipe) Write(b []byte) error {
	if len(b) > p.writeLimit {
		return errors.New("fixture SMB write limit exceeded")
	}
	return p.rpcTestPipe.Write(b)
}

func (p *rpcLimitedTestPipe) Read(maximum int) ([]byte, error) {
	if maximum > p.readLimit {
		return nil, errors.New("fixture SMB read limit exceeded")
	}
	return p.rpcTestPipe.Read(maximum)
}

func (p *rpcTestPipe) Write(b []byte) error {
	p.writes = append(p.writes, append([]byte(nil), b...))
	return nil
}
func (p *rpcTestPipe) Read(maximum int) ([]byte, error) {
	if len(p.reads) == 0 {
		return nil, io.EOF
	}
	b := p.reads[0]
	if len(b) > maximum {
		p.reads[0] = b[maximum:]
		return b[:maximum], nil
	}
	p.reads = p.reads[1:]
	return b, nil
}

func TestRPCBindAndFragmentedPipeCall(t *testing.T) {
	ack := rpcFixtureAck()
	pipe := &rpcTestPipe{reads: [][]byte{ack[:7], ack[7:]}}
	rpc := newRPCClient(pipe)
	if err := rpc.bind(); err != nil {
		t.Fatal(err)
	}
	wantBind, err := hex.DecodeString("05000b03100000004800000001000000b810b810000000000100000000000100c84f324b7016d30112785a47bf6ee18803000000045d888aeb1cc9119fe808002b10486002000000")
	if err != nil || len(pipe.writes) != 1 || !bytes.Equal(pipe.writes[0], wantBind) {
		t.Fatalf("incorrect SRVS/NDR32 bind: %x", pipe.writes)
	}
	stub := bytes.Repeat([]byte{0xa5}, 150)
	want := bytes.Repeat([]byte{0x5a}, 100)
	var stream []byte
	stream = append(stream, rpcFixturePDU(2, 1, 2, want[:40])...)
	stream = append(stream, rpcFixturePDU(2, 0, 2, want[40:80])...)
	stream = append(stream, rpcFixturePDU(2, 2, 2, want[80:])...)
	// Split across headers and coalesce the end of one PDU with the next.
	for len(stream) > 0 {
		n := min(len(stream), 17)
		pipe.reads = append(pipe.reads, stream[:n])
		stream = stream[n:]
	}
	got, err := rpc.call(15, stub)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("fragmented response: %x, %v", got, err)
	}
	var sent []byte
	requests := pipe.writes[1:]
	if len(requests) != 4 {
		t.Fatalf("request was not fragmented to negotiated 64-byte limit: %d", len(requests))
	}
	for i, pdu := range requests {
		flags := byte(0)
		if i == 0 {
			flags |= 1
		}
		if i == len(requests)-1 {
			flags |= 2
		}
		if len(pdu) > 64 || pdu[2] != 0 || pdu[3] != flags || binary.LittleEndian.Uint32(pdu[12:16]) != 2 || binary.LittleEndian.Uint16(pdu[20:22]) != 0 || binary.LittleEndian.Uint16(pdu[22:24]) != 15 {
			t.Fatalf("invalid request fragment: %x", pdu)
		}
		sent = append(sent, pdu[24:]...)
	}
	if !bytes.Equal(sent, stub) {
		t.Fatal("request fragmentation changed its NDR stub")
	}
}

func TestRPCFragmentBuffersRemainIndependent(t *testing.T) {
	want := [][]byte{
		rpcFixturePDU(2, 1, 1, bytes.Repeat([]byte{0x11}, 17)),
		rpcFixturePDU(2, 0, 1, bytes.Repeat([]byte{0x22}, 19)),
		rpcFixturePDU(2, 2, 1, bytes.Repeat([]byte{0x33}, 23)),
	}
	stream := bytes.Join(want, nil)
	firstCut := len(want[0]) + 7
	secondCut := len(want[0]) + len(want[1]) + 9
	rpc := newRPCClient(&rpcTestPipe{reads: [][]byte{stream[:firstCut], stream[firstCut:secondCut], stream[secondCut:]}})
	var retained [][]byte
	for i := range want {
		pdu, err := rpc.readPDU()
		if err != nil || !bytes.Equal(pdu, want[i]) {
			t.Fatalf("fragment %d changed: %x, %v", i, pdu, err)
		}
		retained = append(retained, pdu)
		// An append to a returned fragment must not overwrite the beginning
		// of the next coalesced fragment that readPDU has yet to consume.
		extended := append(pdu, 0xff)
		if extended[len(pdu)] != 0xff {
			t.Fatal("failed to extend fixture fragment")
		}
	}
	for i, pdu := range retained {
		if !bytes.Equal(pdu, want[i]) {
			t.Fatalf("later reads changed retained fragment %d", i)
		}
	}
}

func BenchmarkRPCResponseAssembly(b *testing.B) {
	for _, size := range []struct {
		name string
		n    int
	}{{"4KiB", 4096}, {"128KiB", 128 << 10}} {
		b.Run(size.name, func(b *testing.B) {
			var fragments [][]byte
			for remaining := size.n; remaining > 0; {
				n := min(remaining, rpcFragmentSize-24)
				flags := byte(0)
				if remaining == size.n {
					flags |= 1
				}
				if n == remaining {
					flags |= 2
				}
				fragments = append(fragments, rpcFixturePDU(2, flags, 1, make([]byte, n)))
				remaining -= n
			}
			b.ReportAllocs()
			b.SetBytes(int64(size.n))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				rpc := newRPCClient(&rpcTestPipe{reads: fragments})
				response, err := rpc.call(15, nil)
				if err != nil || len(response) != size.n {
					b.Fatalf("response length %d: %v", len(response), err)
				}
			}
		})
	}
}

func TestRPCBindHonorsSMBTransferLimits(t *testing.T) {
	for _, tt := range []struct {
		name                                       string
		serverSend, serverRecv, wantSend, wantRecv int
	}{
		{"server_cannot_raise_transport_limits", 4096, 4096, 512, 256},
		{"server_can_lower_transport_limits", 128, 160, 160, 128},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ack := rpcFixtureAck()
			binary.LittleEndian.PutUint16(ack[16:18], uint16(tt.serverSend))
			binary.LittleEndian.PutUint16(ack[18:20], uint16(tt.serverRecv))
			pipe := &rpcLimitedTestPipe{rpcTestPipe: &rpcTestPipe{reads: [][]byte{ack}}, writeLimit: 512, readLimit: 256}
			rpc := newRPCClient(pipe)
			if err := rpc.bind(); err != nil {
				t.Fatal(err)
			}
			bind := pipe.writes[0]
			if binary.LittleEndian.Uint16(bind[16:18]) != 512 || binary.LittleEndian.Uint16(bind[18:20]) != 256 || rpc.maxSend != tt.wantSend || rpc.maxRecv != tt.wantRecv {
				t.Fatalf("transport limits lost in bind: advertised=%d/%d negotiated=%d/%d", binary.LittleEndian.Uint16(bind[16:18]), binary.LittleEndian.Uint16(bind[18:20]), rpc.maxSend, rpc.maxRecv)
			}
			want := bytes.Repeat([]byte{0x5a}, 42)
			pipe.reads = append(pipe.reads, rpcFixturePDU(2, 3, 2, want))
			got, err := rpc.call(15, bytes.Repeat([]byte{0xa5}, 700))
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("bounded call: %x, %v", got, err)
			}
			for _, request := range pipe.writes[1:] {
				if len(request) > tt.wantSend {
					t.Fatalf("request exceeded negotiated send size: %d > %d", len(request), tt.wantSend)
				}
			}
		})
	}
	pipe := &rpcLimitedTestPipe{rpcTestPipe: &rpcTestPipe{}, writeLimit: 64, readLimit: 256}
	if err := newRPCClient(pipe).bind(); err == nil || len(pipe.writes) != 0 {
		t.Fatal("attempted bind that does not fit the SMB write limit")
	}
}

func TestRPCBoundsRequestFragmentCountBeforeSending(t *testing.T) {
	// A peer can lower its receive limit after bind. Even a small stub must
	// not cause an excessive number of individual SMB pipe writes.
	for _, size := range []int{4096, 4097} {
		t.Run(fmt.Sprintf("bytes_%d", size), func(t *testing.T) {
			ack := rpcFixtureAck()
			binary.LittleEndian.PutUint16(ack[18:20], 25)
			pipe := &rpcTestPipe{reads: [][]byte{ack, rpcFixturePDU(2, 3, 2, nil)}}
			rpc := newRPCClient(pipe)
			if err := rpc.bind(); err != nil {
				t.Fatal(err)
			}
			_, err := rpc.call(15, bytes.Repeat([]byte{1}, size))
			if size == 4096 {
				if err != nil || len(pipe.writes) != 4097 {
					t.Fatalf("valid bounded fragmentation failed: writes=%d err=%v", len(pipe.writes), err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "fragment safety limit") || len(pipe.writes) != 1 {
				t.Fatalf("unbounded request was sent: writes=%d err=%v", len(pipe.writes), err)
			}
		})
	}
}

func TestRPCBindRejectsInvalidNegotiation(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"call_id", func(b []byte) { b[12] = 2 }},
		{"transfer_syntax", func(b []byte) { b[36] ^= 1 }},
		{"rejected_context", func(b []byte) { b[32] = 2 }},
		{"result_count", func(b []byte) { b[28] = 2 }},
		{"secondary_address_length", func(b []byte) { b[24], b[25] = 0xff, 0xff }},
		{"fragment_too_small", func(b []byte) { b[18] = 24 }},
		{"incomplete_ack", func(b []byte) { b[3] = 1 }},
		{"unnegotiated_auth", func(b []byte) { b[10] = 1 }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ack := rpcFixtureAck()
			tt.mutate(ack)
			if err := newRPCClient(&rpcTestPipe{reads: [][]byte{ack}}).bind(); err == nil {
				t.Fatal("accepted invalid bind acknowledgement")
			}
		})
	}
}

func TestRPCRejectsMalformedResponses(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"call_id", func(b []byte) { b[12] = 2 }},
		{"wrong_type", func(b []byte) { b[2] = 0 }},
		{"missing_first", func(b []byte) { b[3] = 2 }},
		{"context_id", func(b []byte) { b[20] = 1 }},
		{"allocation_hint", func(b []byte) { binary.LittleEndian.PutUint32(b[16:20], rpcMaxStub+1) }},
		{"big_endian", func(b []byte) { b[4] = 0 }},
		{"unnegotiated_auth", func(b []byte) { b[10] = 1 }},
		{"huge_fragment", func(b []byte) { b[8], b[9] = 0xff, 0xff }},
		{"short_header", func(b []byte) { b[8] = 15 }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pdu := rpcFixturePDU(2, 3, 1, []byte{1, 2, 3, 4})
			tt.mutate(pdu)
			if _, err := newRPCClient(&rpcTestPipe{reads: [][]byte{pdu}}).call(15, nil); err == nil {
				t.Fatal("accepted invalid RPC response")
			}
		})
	}
	for _, packets := range [][][]byte{
		{rpcFixturePDU(2, 1, 1, nil)},
		{rpcFixturePDU(2, 1, 1, []byte{1}), rpcFixturePDU(2, 3, 1, []byte{2})},
	} {
		if _, err := newRPCClient(&rpcTestPipe{reads: packets}).call(15, nil); err == nil {
			t.Fatal("accepted non-progressing or repeated-first fragment")
		}
	}
	fault := rpcFixturePDU(3, 3, 1, []byte{5, 0, 0, 0, 0, 0, 0, 0})
	if _, err := newRPCClient(&rpcTestPipe{reads: [][]byte{fault}}).call(15, nil); !errors.Is(err, ErrRPCDenied) {
		t.Fatalf("RPC access-denied fault lost: %v", err)
	}
}

func TestEncodeShareRequestNDR32(t *testing.T) {
	want, err := hex.DecodeString(strings.Join([]string{
		"00000200", "07000000", "00000000", "07000000", "5c005c0068006f007300740000000000",
		"01000000", "01000000", "04000200", "00000000", "00000000", "00000100", "08000200", "07000000",
	}, ""))
	if err != nil {
		t.Fatal(err)
	}
	got, err := encodeShareRequest("host", 7)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("NDR32 request = %x, %v; want %x", got, err, want)
	}
	for _, bad := range []string{"bad\x00host", "\xff", strings.Repeat("x", 1025)} {
		if _, err := encodeShareRequest(bad, 0); err == nil {
			t.Fatal("accepted invalid RPC hostname")
		}
	}
}

func TestRPCFaultRequiresCompleteMatchingContext(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"missing_first", func(b []byte) { b[3] = 2 }},
		{"missing_last", func(b []byte) { b[3] = 1 }},
		{"context_id", func(b []byte) { b[20] = 1 }},
	} {
		for _, binding := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/bind=%t", tt.name, binding), func(t *testing.T) {
				fault := rpcFixturePDU(3, 3, 1, []byte{5, 0, 0, 0, 0, 0, 0, 0})
				tt.mutate(fault)
				rpc := newRPCClient(&rpcTestPipe{reads: [][]byte{fault}})
				var err error
				if binding {
					err = rpc.bind()
				} else {
					_, err = rpc.call(15, nil)
				}
				if err == nil || errors.Is(err, ErrRPCDenied) {
					t.Fatalf("malformed fault treated as a server permission decision: %v", err)
				}
			})
		}
	}
	// A complete runtime fault can carry DID_NOT_EXECUTE. MS-RPCE requires
	// clients to ignore any fault stub, rather than decoding it as share data.
	fault := rpcFixturePDU(3, 0x23, 1, []byte{5, 0, 0, 0, 0, 0, 0, 0, 0xaa})
	if _, err := newRPCClient(&rpcTestPipe{reads: [][]byte{fault}}).call(15, nil); !errors.Is(err, ErrRPCDenied) {
		t.Fatalf("valid complete fault lost: %v", err)
	}
}

func TestDecodeSharePage(t *testing.T) {
	want := []Share{{Name: "data$", Comment: "fixture", Type: 0x80000000}, {Name: "資料😀", Type: 3}}
	page, err := decodeSharePage(rpcFixturePage(want, 234, 42))
	if err != nil || !reflect.DeepEqual(page.shares, want) || !page.hasResume || page.resume != 42 || page.status != 234 {
		t.Fatalf("decoded page = %+v, %v", page, err)
	}
	// A null container and null resume handle are valid empty responses.
	null, _ := hex.DecodeString("010000000100000000000000000000000000000000000000")
	page, err = decodeSharePage(null)
	if err != nil || len(page.shares) != 0 || page.hasResume || page.status != 0 {
		t.Fatalf("null container: %+v, %v", page, err)
	}
}

func BenchmarkDecodeSharePage(b *testing.B) {
	for _, comment := range []struct{ name, text string }{
		{"ASCII", strings.Repeat("shared documents ", 16)},
		{"Unicode", strings.Repeat("資料😀é ", 32)},
	} {
		b.Run(comment.name, func(b *testing.B) {
			shares := make([]Share, 1000)
			for i := range shares {
				shares[i] = Share{Name: fmt.Sprintf("share-%d", i), Comment: comment.text}
			}
			data := rpcFixturePage(shares, 0, 0)
			b.ReportAllocs()
			b.SetBytes(int64(len(data)))
			for b.Loop() {
				page, err := decodeSharePage(data)
				if err != nil || len(page.shares) != len(shares) {
					b.Fatalf("decode page: count=%d, err=%v", len(page.shares), err)
				}
			}
		})
	}
}

func TestDecodeSharePageRejectsMalformedNDR(t *testing.T) {
	base := rpcFixturePage([]Share{{Name: "data", Comment: "remark"}}, 0, 0)
	for n := 0; n < len(base); n++ {
		if _, err := decodeSharePage(base[:n]); err == nil {
			t.Fatalf("accepted truncation at byte %d", n)
		}
	}
	for _, tt := range []struct {
		name   string
		offset int
		value  uint32
	}{
		{"level", 0, 2}, {"discriminator", 4, 2}, {"count_limit", 12, 16385}, {"null_array_with_entries", 16, 0},
		{"conformance", 20, 2}, {"string_maximum", 36, 0xffffffff}, {"string_offset", 40, 6}, {"string_count", 44, 0xffffffff},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b := append([]byte(nil), base...)
			binary.LittleEndian.PutUint32(b[tt.offset:tt.offset+4], tt.value)
			if _, err := decodeSharePage(b); err == nil {
				t.Fatal("accepted malformed NDR")
			}
		})
	}
	for _, at := range []int{48, 56} {
		b := append([]byte(nil), base...)
		binary.LittleEndian.PutUint16(b[at:at+2], 0xdc00)
		if _, err := decodeSharePage(b); err == nil {
			t.Fatal("accepted unpaired UTF-16 or missing terminator")
		}
	}
	if _, err := decodeSharePage(append(base, 0)); err == nil {
		t.Fatal("accepted trailing data")
	}
}

func TestNDRShareTextUTF16(t *testing.T) {
	for _, tc := range []struct {
		name  string
		units []uint16
		want  string
		valid bool
	}{
		{"empty", []uint16{0}, "", true},
		{"encoding_boundaries", []uint16{0x41, 0x7f, 0x80, 0x7ff, 0x800, 0xd7ff, 0xe000, 0xffff, 0xd800, 0xdc00, 0xdbff, 0xdfff, 0}, "A\x7f\u0080\u07ff\u0800\ud7ff\ue000\uffff\U00010000\U0010ffff", true},
		{"zero_count", nil, "", false},
		{"missing_terminator", []uint16{0x41}, "", false},
		{"embedded_zero", []uint16{0x41, 0, 0x42, 0}, "", false},
		{"unpaired_low", []uint16{0xdc00, 0}, "", false},
		{"unpaired_high", []uint16{0xd800, 0}, "", false},
		{"high_then_high", []uint16{0xd800, 0xd800, 0}, "", false},
		{"high_then_bmp", []uint16{0xd800, 0x41, 0}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Nonzero varying-array offsets are valid NDR32. The encoded count
			// includes the terminator; the next scalar starts after alignment.
			var data []byte
			for _, value := range []uint32{uint32(len(tc.units) + 2), 2, uint32(len(tc.units))} {
				data = binary.LittleEndian.AppendUint32(data, value)
			}
			for _, unit := range tc.units {
				data = binary.LittleEndian.AppendUint16(data, unit)
			}
			for len(data)%4 != 0 {
				data = append(data, 0)
			}
			data = binary.LittleEndian.AppendUint32(data, 0xfeedface)
			r := ndrShareReader{data: data}
			got := r.text()
			if (r.err == nil) != tc.valid || got != tc.want {
				t.Fatalf("decoded text %q, error %v; want %q, valid=%t", got, r.err, tc.want, tc.valid)
			}
			if tc.valid {
				if next := r.u32(); next != 0xfeedface || r.err != nil {
					t.Fatalf("decoder lost next aligned field: %#x, %v", next, r.err)
				}
				clear(data)
				if got != tc.want {
					t.Fatal("decoded string retained mutable response storage")
				}
			}
		})
	}
}

func TestEnumerationFollowsResumeCursorAndKeepsHiddenShares(t *testing.T) {
	calls := 0
	shares, err := enumeratePages("fixture", func(body []byte) ([]byte, error) {
		if len(body) < 48 {
			t.Fatal("truncated enumeration request")
		}
		units := binary.LittleEndian.Uint32(body[12:16])
		levelAt := (16 + int(units)*2 + 3) &^ 3
		if levelAt > len(body)-32 || binary.LittleEndian.Uint32(body[levelAt:levelAt+4]) != 1 {
			t.Fatal("invalid level-1 enumeration request")
		}
		calls++
		if calls == 1 {
			if binary.LittleEndian.Uint32(body[len(body)-4:]) != 0 {
				t.Fatal("initial enumeration cursor is not zero")
			}
			return rpcFixturePage([]Share{{Name: "data"}, {Name: "hidden$"}}, 234, 7), nil
		}
		if calls != 2 || binary.LittleEndian.Uint32(body[len(body)-8:len(body)-4]) == 0 || binary.LittleEndian.Uint32(body[len(body)-4:]) != 7 {
			t.Fatal("incorrect pagination cursor or extra request")
		}
		return rpcFixturePage([]Share{{Name: "DATA"}, {Name: "last"}}, 0, 0), nil
	})
	if err != nil || calls != 2 || len(shares) != 3 || shares[1].Name != "hidden$" || shares[2].Name != "last" {
		t.Fatalf("enumeration: %+v, %v, calls=%d", shares, err, calls)
	}
}

func TestEnumerationStopsOnRepeatedCursor(t *testing.T) {
	calls := 0
	shares, err := enumeratePages("fixture", func([]byte) ([]byte, error) {
		calls++
		return rpcFixturePage([]Share{{Name: "data"}}, 234, 5), nil
	})
	if err == nil || calls != 2 || len(shares) != 1 {
		t.Fatalf("repeated cursor was not bounded: calls=%d shares=%v error=%v", calls, shares, err)
	}
}

func TestEnumerationDeniedDoesNotRetry(t *testing.T) {
	calls := 0
	_, err := enumeratePages("fixture", func([]byte) ([]byte, error) {
		calls++
		return rpcFixturePage(nil, 5, 0), nil
	})
	if !errors.Is(err, ErrRPCDenied) || calls != 1 {
		t.Fatalf("access denial: calls=%d error=%v", calls, err)
	}
}

func TestEnumeratePagesPreservesCompletedPagesAndCapsPagination(t *testing.T) {
	calls := 0
	failure := errors.New("fixture connection failure")
	shares, err := enumeratePages("host", func([]byte) ([]byte, error) {
		calls++
		if calls == 1 {
			return rpcFixturePage([]Share{{Name: "data"}}, 234, 7), nil
		}
		return nil, failure
	})
	if !errors.Is(err, failure) || len(shares) != 1 || shares[0].Name != "data" {
		t.Fatalf("lost completed page: %+v, %v", shares, err)
	}
	calls = 0
	_, err = enumeratePages("host", func([]byte) ([]byte, error) { calls++; return rpcFixturePage(nil, 234, uint32(calls)), nil })
	if err == nil || calls != 256 {
		t.Fatalf("pagination not capped: calls=%d err=%v", calls, err)
	}
	for _, status := range []uint32{5, 124} {
		_, err := enumeratePages("host", func([]byte) ([]byte, error) { return rpcFixturePage(nil, status, 0), nil })
		if err == nil || (status == 5 && !errors.Is(err, ErrRPCDenied)) {
			t.Fatalf("status %d lost: %v", status, err)
		}
	}
}

func TestEnumeratePagesBoundsRetainedText(t *testing.T) {
	// Every page and individual string is valid; only the accumulated result
	// exceeds the cap. A count-only limit would allow gigabytes of comments.
	comment := strings.Repeat("x", 65535)
	calls := 0
	shares, err := enumeratePages("host", func([]byte) ([]byte, error) {
		page := make([]Share, 32)
		for i := range page {
			page[i] = Share{Name: fmt.Sprintf("share-%d-%d", calls, i), Comment: comment}
		}
		calls++
		return rpcFixturePage(page, 234, uint32(calls)), nil
	})
	if err == nil || !strings.Contains(err.Error(), "text safety limit") || calls != 8 {
		t.Fatalf("aggregate text was not bounded: pages=%d shares=%d err=%v", calls, len(shares), err)
	}
	retained := 0
	for _, share := range shares {
		retained += len(share.Name) + len(share.Comment)
	}
	if retained > 16<<20 {
		t.Fatalf("retained %d bytes past text budget", retained)
	}
}

func FuzzDecodeSharePage(f *testing.F) {
	f.Add(rpcFixturePage([]Share{{Name: "data$", Comment: "test"}}, 0, 0))
	f.Add(rpcFixturePage(nil, 234, 1))
	f.Add([]byte{1, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		page, err := decodeSharePage(b)
		if err == nil && len(page.shares) > 16384 {
			t.Fatal("share bound exceeded")
		}
	})
}

func FuzzRPCResponse(f *testing.F) {
	f.Add(rpcFixturePDU(2, 3, 1, []byte{1, 2, 3, 4}))
	f.Add([]byte{5, 0, 2, 3})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = newRPCClient(&rpcTestPipe{reads: [][]byte{b}}).call(15, nil) })
}
