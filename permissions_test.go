package main

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/jfjallid/go-smb/smb"
)

func permissionContext(name string, data []byte) []byte {
	size := 24
	if len(data) > 0 {
		size += len(data)
	}
	buf := make([]byte, size)
	binary.LittleEndian.PutUint16(buf[4:6], 16)
	binary.LittleEndian.PutUint16(buf[6:8], uint16(len(name)))
	copy(buf[16:20], name)
	if len(data) > 0 {
		binary.LittleEndian.PutUint16(buf[10:12], 24)
		binary.LittleEndian.PutUint32(buf[12:16], uint32(len(data)))
		copy(buf[24:], data)
	}
	return buf
}

func maximalAccessResponse(status, mask uint32) []byte {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint32(data[:4], status)
	binary.LittleEndian.PutUint32(data[4:], mask)
	return permissionContext("MxAc", data)
}

func permissionContextList(entries ...[]byte) []byte {
	var buf []byte
	for i, original := range entries {
		entry := append([]byte(nil), original...)
		if i+1 < len(entries) {
			for len(entry)%8 != 0 {
				entry = append(entry, 0)
			}
			binary.LittleEndian.PutUint32(entry[:4], uint32(len(entry)))
		}
		buf = append(buf, entry...)
	}
	return buf
}

func TestAddMaximalAccessContextReadOnlyWireRequest(t *testing.T) {
	s := &smb.Session{}
	req, err := s.NewCreateReq("share", "", smb.OpLockLevelNone,
		smb.ImpersonationLevelImpersonation, smb.DAccMaskFileListDirectory,
		smb.FileAttrDirectory, smb.FileShareRead|smb.FileShareWrite|smb.FileShareDelete,
		smb.FileOpen, smb.FileDirectoryFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := addMaximalAccessContext(&req); err != nil {
		t.Fatal(err)
	}
	wire, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var got smb.CreateReq
	if err := got.UnmarshalBinary(wire); err != nil {
		t.Fatal(err)
	}
	if got.DesiredAccess != smb.DAccMaskFileListDirectory || got.CreateDisposition != smb.FileOpen || got.CreateOptions != smb.FileDirectoryFile {
		t.Fatalf("context changed the read-only open: access=%#x disposition=%#x options=%#x", got.DesiredAccess, got.CreateDisposition, got.CreateOptions)
	}
	if got.NameLength != 0 || got.NameOffset != 120 || got.CreateContextsOffset != 128 || got.CreateContextsLength != 24 {
		t.Fatalf("incorrect root CREATE wire layout: name=%d/%d contexts=%d/%d", got.NameOffset, got.NameLength, got.CreateContextsOffset, got.CreateContextsLength)
	}
	ctx := wire[got.CreateContextsOffset:]
	if len(ctx) != 24 || string(ctx[16:20]) != "MxAc" || binary.LittleEndian.Uint32(ctx[:4]) != 0 || binary.LittleEndian.Uint32(ctx[12:16]) != 0 {
		t.Fatal("expected exactly one maximal-access request without a timestamp")
	}
}

func TestAddMaximalAccessContextRejectsNonRootOrExistingContexts(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  *smb.CreateReq
	}{
		{"nil", nil},
		{"named file", &smb.CreateReq{NameLength: 2}},
		{"existing offset", &smb.CreateReq{CreateContextsOffset: 128}},
		{"existing length", &smb.CreateReq{CreateContextsLength: 24}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := addMaximalAccessContext(tc.req); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestParseMaximalAccess(t *testing.T) {
	for _, tc := range []struct {
		name  string
		buf   []byte
		mask  uint32
		known bool
	}{
		{"empty", nil, 0, false},
		{"absent", permissionContext("QFid", nil), 0, false},
		{"allowed", maximalAccessResponse(0, 0x001f01ff), 0x001f01ff, true},
		{"denied", maximalAccessResponse(0, 0), 0, true},
		{"between unknown contexts", permissionContextList(permissionContext("QFid", nil), maximalAccessResponse(0, 2), permissionContext("TWrp", make([]byte, 8))), 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mask, known, err := parseMaximalAccess(tc.buf)
			if err != nil || mask != tc.mask || known != tc.known {
				t.Fatalf("got mask=%#x known=%v err=%v; want mask=%#x known=%v", mask, known, err, tc.mask, tc.known)
			}
		})
	}
}

func TestParseMaximalAccessRejectsMalformedContexts(t *testing.T) {
	mutated := func(change func([]byte)) []byte {
		buf := maximalAccessResponse(0, 2)
		change(buf)
		return buf
	}
	for _, tc := range []struct {
		name string
		buf  []byte
	}{
		{"short header", make([]byte, 15)},
		{"next below header", mutated(func(b []byte) { binary.LittleEndian.PutUint32(b[:4], 8) })},
		{"unaligned next", mutated(func(b []byte) { binary.LittleEndian.PutUint32(b[:4], 31) })},
		{"next at end", mutated(func(b []byte) { binary.LittleEndian.PutUint32(b[:4], uint32(len(b))) })},
		{"huge next", mutated(func(b []byte) { binary.LittleEndian.PutUint32(b[:4], 0xfffffff8) })},
		{"name inside header", mutated(func(b []byte) { binary.LittleEndian.PutUint16(b[4:6], 8) })},
		{"unaligned name", mutated(func(b []byte) { binary.LittleEndian.PutUint16(b[4:6], 17) })},
		{"short name", mutated(func(b []byte) { binary.LittleEndian.PutUint16(b[6:8], 3) })},
		{"name beyond end", mutated(func(b []byte) { binary.LittleEndian.PutUint16(b[4:6], 65528) })},
		{"huge name length", mutated(func(b []byte) { binary.LittleEndian.PutUint16(b[6:8], 65535) })},
		{"data inside header", mutated(func(b []byte) { binary.LittleEndian.PutUint16(b[10:12], 8) })},
		{"unaligned data", mutated(func(b []byte) { binary.LittleEndian.PutUint16(b[10:12], 23) })},
		{"data beyond end", mutated(func(b []byte) { binary.LittleEndian.PutUint16(b[10:12], 65528) })},
		{"huge data length", mutated(func(b []byte) { binary.LittleEndian.PutUint32(b[12:16], 0xffffffff) })},
		{"overlapping name and data", mutated(func(b []byte) { binary.LittleEndian.PutUint16(b[10:12], 16) })},
		{"short maximal-access data", permissionContext("MxAc", make([]byte, 7))},
		{"long maximal-access data", permissionContext("MxAc", make([]byte, 9))},
		{"no maximal-access data", permissionContext("MxAc", nil)},
		{"duplicate", permissionContextList(maximalAccessResponse(0, 2), maximalAccessResponse(0, 2))},
		{"malformed context after valid result", permissionContextList(maximalAccessResponse(0, 2), make([]byte, 15))},
		{"name spills into next context", permissionContextList(mutated(func(b []byte) { binary.LittleEndian.PutUint16(b[6:8], 24) }), permissionContext("QFid", nil))},
		{"data spills into next context", permissionContextList(mutated(func(b []byte) { binary.LittleEndian.PutUint32(b[12:16], 16) }), permissionContext("QFid", nil))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mask, known, err := parseMaximalAccess(tc.buf)
			if err == nil || known || mask != 0 {
				t.Fatalf("malformed data produced mask=%#x known=%v err=%v", mask, known, err)
			}
		})
	}
}

func TestParseMaximalAccessNonzeroStatusIsUnknown(t *testing.T) {
	mask, known, err := parseMaximalAccess(maximalAccessResponse(smb.StatusAccessDenied, 0xffffffff))
	if mask != 0 || known || err == nil || !strings.Contains(err.Error(), "0xc0000022") {
		t.Fatalf("got mask=%#x known=%v err=%v", mask, known, err)
	}
}

func TestParseMaximalAccessContextLimit(t *testing.T) {
	entries := make([][]byte, 65)
	for i := range entries {
		entries[i] = permissionContext("QFid", nil)
	}
	if _, known, err := parseMaximalAccess(permissionContextList(entries[:64]...)); known || err != nil {
		t.Fatalf("64 contexts: known=%v err=%v", known, err)
	}
	if _, known, err := parseMaximalAccess(permissionContextList(entries...)); known || err == nil {
		t.Fatalf("65 contexts: known=%v err=%v", known, err)
	}
}

func TestRootWritePermission(t *testing.T) {
	for _, tc := range []struct {
		name       string
		shareMask  uint32
		shareKnown bool
		rootMask   uint32
		rootKnown  bool
		state      string
		basis      string
	}{
		{"both allow", 2, true, 2, true, Allowed, "share_and_root_metadata"},
		{"share denies", 1, true, 2, true, Denied, "share_and_root_metadata"},
		{"root denies", 2, true, 1, true, Denied, "share_and_root_metadata"},
		{"zero share denies", 0, true, 2, true, Denied, "share_and_root_metadata"},
		{"zero root denies", 2, true, 0, true, Denied, "share_and_root_metadata"},
		{"positive share alone", 2, true, 0, false, Unknown, "share_metadata"},
		{"positive root alone", 0, false, 2, true, Unknown, "root_metadata"},
		{"negative share alone", 0, true, 2, false, Denied, "share_metadata"},
		{"negative root alone", 2, false, 0, true, Denied, "root_metadata"},
		{"neither known", 2, false, 2, false, Unknown, "unavailable"},
		{"generic write share", 0x40000000, true, 2, true, Allowed, "share_and_root_metadata"},
		{"generic write root", 2, true, 0x40000000, true, Allowed, "share_and_root_metadata"},
		{"different generic masks", 0x10000000, true, 0x40000000, true, Allowed, "share_and_root_metadata"},
		{"different generic masks reversed", 0x40000000, true, 0x10000000, true, Allowed, "share_and_root_metadata"},
		{"generic read cannot add files", 0x80000000, true, 0x10000000, true, Denied, "share_and_root_metadata"},
		{"generic execute cannot add files", 0x10000000, true, 0x20000000, true, Denied, "share_and_root_metadata"},
		{"add subdirectory alone cannot add files", 4, true, 0x10000000, true, Denied, "share_and_root_metadata"},
		{"generic share alone remains unknown", 0x10000000, true, 0, false, Unknown, "share_metadata"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state, basis := rootWritePermission(tc.shareMask, tc.shareKnown, tc.rootMask, tc.rootKnown)
			if state != tc.state || basis != tc.basis {
				t.Fatalf("got %s/%s; want %s/%s", state, basis, tc.state, tc.basis)
			}
		})
	}
}

func FuzzParseMaximalAccess(f *testing.F) {
	f.Add([]byte{})
	f.Add(maximalAccessResponse(0, 2))
	f.Add(permissionContextList(permissionContext("QFid", nil), maximalAccessResponse(0, 0)))
	f.Fuzz(func(t *testing.T, buf []byte) {
		mask, known, err := parseMaximalAccess(buf)
		if err != nil && (known || mask != 0) {
			t.Fatalf("parse error must not produce trusted rights: mask=%#x known=%v err=%v", mask, known, err)
		}
	})
}
