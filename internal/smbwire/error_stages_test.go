package smbwire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
)

func TestNewConnectionErrorsRetainStageAndCause(t *testing.T) {
	negotiate := make([]byte, 64)
	binary.LittleEndian.PutUint16(negotiate, 65)
	binary.LittleEndian.PutUint16(negotiate[2:], 1)
	binary.LittleEndian.PutUint16(negotiate[4:], 0x210)
	for _, offset := range []int{28, 32, 36} {
		binary.LittleEndian.PutUint32(negotiate[offset:], 65536)
	}
	dialFailure := errors.New("fixture dial failure")
	for _, tc := range []struct {
		name, stage string
		command     uint16
		status      uint32
		dialError   error
	}{
		{name: "dial", stage: "TCP dial", dialError: dialFailure},
		{name: "negotiate EOF", stage: "SMB negotiation"},
		{name: "negotiate rejection", stage: "SMB negotiation", status: StatusAccessDenied},
		{name: "authenticate EOF", stage: "SMB authentication", command: SessionSetupCommand},
		{name: "authenticate rejection", stage: "SMB authentication", command: SessionSetupCommand, status: StatusLogonFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var replies []byte
			if tc.command == SessionSetupCommand {
				replies = stageTestResponse(0, 0, 0, negotiate)
			}
			if tc.status != 0 {
				replies = append(replies, stageTestResponse(uint64(tc.command), tc.command, tc.status, nil)...)
			}
			wire := &responseConn{Reader: bytes.NewReader(replies)}
			attempts := 0
			conn, err := NewConnection(Options{Dial: func() (net.Conn, error) {
				attempts++
				return wire, tc.dialError
			}})
			if conn != nil || err == nil || !strings.HasPrefix(err.Error(), tc.stage+": ") || attempts != 1 {
				t.Fatalf("conn=%v error=%v attempts=%d; want stage %q and one attempt", conn, err, attempts, tc.stage)
			}
			if tc.dialError != nil {
				if !errors.Is(err, tc.dialError) {
					t.Fatalf("lost dial cause: %v", err)
				}
			} else {
				assertStageCause(t, err, tc.command, tc.status)
				if !wire.closed {
					t.Fatal("failed connection left its transport open")
				}
			}
		})
	}
}

func TestEnumerationErrorsRetainStageAndCause(t *testing.T) {
	for _, tc := range []struct {
		stage   string
		step    int
		command uint16
	}{
		{"connect IPC$", 0, 3},
		{"open srvsvc pipe", 1, 5},
		{"bind srvsvc RPC", 2, 9},
		{"NetrShareEnum", 4, 9},
	} {
		for _, status := range []uint32{0, StatusAccessDenied} {
			name := tc.stage + "/EOF"
			if status != 0 {
				name = tc.stage + "/rejection"
			}
			t.Run(name, func(t *testing.T) {
				replies := bytes.Join(stageTestEnumerationPrefix()[:tc.step], nil)
				if status != 0 {
					replies = append(replies, stageTestResponse(uint64(tc.step), tc.command, status, nil)...)
				}
				c, wire := connectionWithResponse(0, 0, 0, nil)
				wire.Reader = bytes.NewReader(replies)
				c.opts.Host, c.maxRead, c.maxWrite = "fixture", 4280, 4280
				result, err := c.EnumerateShares()
				if err == nil || !strings.HasPrefix(err.Error(), tc.stage+": ") || result.Complete {
					t.Fatalf("result=%+v error=%v; want stage %q", result, err, tc.stage)
				}
				assertStageCause(t, err, tc.command, status)
				// EOF during cleanup must not replace a primary typed rejection.
				if status != 0 && tc.step > 0 && result.Failure != err {
					t.Fatalf("cleanup replaced the primary enumeration failure: %+v, %v", result, err)
				}
			})
		}
	}
}

func TestEnumerationPageErrorsRetainStageAndDenial(t *testing.T) {
	for _, denied := range []bool{false, true} {
		page := []byte{0} // Truncated NDR, after a successful RPC exchange.
		if denied {
			page = rpcFixturePage(nil, 5, 0)
		}
		replies := stageTestEnumerationPrefix()
		replies = append(replies, stageTestResponse(5, 8, 0, stageTestReadBody(rpcFixturePDU(2, 3, 2, page))))
		closeBody := make([]byte, 60)
		binary.LittleEndian.PutUint16(closeBody, 60)
		replies = append(replies, stageTestResponse(6, 6, 0, closeBody), stageTestResponse(7, 4, 0, []byte{4, 0, 0, 0}))
		c, wire := connectionWithResponse(0, 0, 0, nil)
		wire.Reader = bytes.NewReader(bytes.Join(replies, nil))
		c.opts.Host, c.maxRead, c.maxWrite = "fixture", 4280, 4280
		result, err := c.EnumerateShares()
		if err == nil || !strings.HasPrefix(err.Error(), "NetrShareEnum: ") || result.Failure != err || result.Complete {
			t.Fatalf("denied=%t result=%+v error=%v", denied, result, err)
		}
		if errors.Is(err, ErrRPCDenied) != denied || (!denied && !strings.Contains(err.Error(), "decode share list")) {
			t.Fatalf("lost page failure cause: %v", err)
		}
		if wire.closed || wire.Len() != 0 {
			t.Fatal("enumeration failure changed successful pipe/tree cleanup")
		}
	}
}

func assertStageCause(t *testing.T, err error, command uint16, status uint32) {
	t.Helper()
	if status == 0 {
		if !errors.Is(err, io.EOF) {
			t.Fatalf("lost EOF cause: %v", err)
		}
		return
	}
	var rejection *NTStatusError
	if !errors.As(err, &rejection) || rejection.Command != command || rejection.Status != status {
		t.Fatalf("lost typed rejection for command %d status %#x: %v", command, status, err)
	}
}

func stageTestResponse(id uint64, command uint16, status uint32, body []byte) []byte {
	if status != 0 {
		body = []byte{9, 0, 0, 0, 0, 0, 0, 0}
	}
	_, wire := connectionWithResponse(command, 9, status, body)
	packet, _ := io.ReadAll(wire)
	binary.LittleEndian.PutUint64(packet[4+24:], id)
	return packet
}

func stageTestReadBody(data []byte) []byte {
	body := make([]byte, 16+len(data))
	binary.LittleEndian.PutUint16(body, 17)
	body[2] = 80
	binary.LittleEndian.PutUint32(body[4:], uint32(len(data)))
	copy(body[16:], data)
	return body
}

func stageTestEnumerationPrefix() [][]byte {
	treeBody := make([]byte, 16)
	binary.LittleEndian.PutUint16(treeBody, 16)
	treeBody[2] = 2
	createBody := make([]byte, 88)
	binary.LittleEndian.PutUint16(createBody, 89)
	binary.LittleEndian.PutUint32(createBody[4:], 1)
	writeBody := make([]byte, 16)
	binary.LittleEndian.PutUint16(writeBody, 17)
	binary.LittleEndian.PutUint32(writeBody[4:], 72)
	ack := rpcFixtureAck()
	binary.LittleEndian.PutUint16(ack[16:], 4280)
	binary.LittleEndian.PutUint16(ack[18:], 4280)
	request, _ := encodeShareRequest("fixture", 0)
	callWriteBody := bytes.Clone(writeBody)
	binary.LittleEndian.PutUint32(callWriteBody[4:], uint32(24+len(request)))
	return [][]byte{
		stageTestResponse(0, 3, 0, treeBody),
		stageTestResponse(1, 5, 0, createBody),
		stageTestResponse(2, 9, 0, writeBody),
		stageTestResponse(3, 8, 0, stageTestReadBody(ack)),
		stageTestResponse(4, 9, 0, callWriteBody),
	}
}
