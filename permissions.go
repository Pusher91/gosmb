package main

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/jfjallid/go-smb/smb"
)

// addMaximalAccessContext asks the server for the caller's maximal access to
// the existing share root. MxAc has no payload: omitting the timestamp requests
// an unconditional answer and does not change the access requested by the open.
func addMaximalAccessContext(req *smb.CreateReq) error {
	if req == nil {
		return errors.New("cannot add maximal-access context to a nil request")
	}
	if req.NameLength != 0 {
		return errors.New("maximal-access request must open the share root")
	}
	if req.CreateContextsOffset != 0 || req.CreateContextsLength != 0 {
		return errors.New("maximal-access request already contains create contexts")
	}

	// The CREATE's fixed header and body occupy 120 bytes. Keep eight bytes
	// of empty-name padding, then one 24-byte, eight-byte-aligned context.
	buf := make([]byte, 8+24)
	ctx := buf[8:]
	binary.LittleEndian.PutUint16(ctx[4:6], 16) // NameOffset, relative to context.
	binary.LittleEndian.PutUint16(ctx[6:8], 4)  // NameLength.
	copy(ctx[16:20], "MxAc")
	// Next, Reserved, DataOffset and DataLength remain zero.
	req.NameOffset = 120
	req.Buffer = buf
	req.CreateContextsOffset = 128
	req.CreateContextsLength = 24
	return nil
}

// parseMaximalAccess accepts only the CREATE response's context buffer, not
// its SMB header. Validate the entire list before trusting a result: a valid
// MxAc followed by malformed or duplicate contexts must not grant permission.
func parseMaximalAccess(buf []byte) (mask uint32, known bool, err error) {
	if len(buf) == 0 {
		return 0, false, nil
	}
	const maxContexts = 64
	var found bool
	var queryErr error
	for offset, count := 0, 0; ; count++ {
		if count >= maxContexts {
			return 0, false, errors.New("too many SMB create contexts")
		}
		if len(buf)-offset < 16 {
			return 0, false, errors.New("truncated SMB create context header")
		}
		remaining := buf[offset:]
		next := uint64(binary.LittleEndian.Uint32(remaining[:4]))
		entryLength := uint64(len(remaining))
		if next != 0 {
			if next < 16 || next%8 != 0 || next >= entryLength {
				return 0, false, errors.New("invalid SMB create context next offset")
			}
			entryLength = next
		}
		entry := remaining[:int(entryLength)]
		nameOffset := uint64(binary.LittleEndian.Uint16(entry[4:6]))
		nameLength := uint64(binary.LittleEndian.Uint16(entry[6:8]))
		dataOffset := uint64(binary.LittleEndian.Uint16(entry[10:12]))
		dataLength := uint64(binary.LittleEndian.Uint32(entry[12:16]))
		if nameOffset < 16 || nameOffset%8 != 0 || nameLength < 4 || nameOffset+nameLength > entryLength {
			return 0, false, errors.New("invalid SMB create context name bounds")
		}
		if dataLength != 0 {
			if dataOffset < 16 || dataOffset%8 != 0 || dataOffset+dataLength > entryLength {
				return 0, false, errors.New("invalid SMB create context data bounds")
			}
			if nameOffset < dataOffset+dataLength && dataOffset < nameOffset+nameLength {
				return 0, false, errors.New("overlapping SMB create context name and data")
			}
		}
		name := entry[int(nameOffset):int(nameOffset+nameLength)]
		if string(name) == "MxAc" {
			if found {
				return 0, false, errors.New("duplicate SMB maximal-access context")
			}
			found = true
			if dataLength != 8 {
				return 0, false, errors.New("invalid SMB maximal-access response length")
			}
			data := entry[int(dataOffset):int(dataOffset+dataLength)]
			status := binary.LittleEndian.Uint32(data[:4])
			if status != smb.StatusOk {
				queryErr = fmt.Errorf("server could not report root maximal access (status 0x%08x)", status)
			} else {
				mask = binary.LittleEndian.Uint32(data[4:8])
			}
		}
		if next == 0 {
			if queryErr != nil {
				return 0, false, queryErr
			}
			return mask, found, nil
		}
		offset += int(next)
	}
}

// normalizeDirectoryAccess expands generic rights separately for each ACL
// layer before intersecting them. Directory bit 0x2 is FILE_ADD_FILE, not a
// permission to modify all files already present in the directory.
func normalizeDirectoryAccess(mask uint32) uint32 {
	const (
		genericRead    uint32 = 0x80000000
		genericWrite   uint32 = 0x40000000
		genericExecute uint32 = 0x20000000
		genericAll     uint32 = 0x10000000
	)
	result := mask &^ (genericRead | genericWrite | genericExecute | genericAll)
	if mask&genericRead != 0 {
		result |= 0x00120089 // READ_CONTROL, SYNCHRONIZE, LIST_DIRECTORY, READ_EA, READ_ATTRIBUTES.
	}
	if mask&genericWrite != 0 {
		result |= 0x00120116 // READ_CONTROL, SYNCHRONIZE, ADD_FILE, ADD_SUBDIRECTORY, WRITE_EA, WRITE_ATTRIBUTES.
	}
	if mask&genericExecute != 0 {
		result |= 0x001200a0 // READ_CONTROL, SYNCHRONIZE, TRAVERSE, READ_ATTRIBUTES.
	}
	if mask&genericAll != 0 {
		result |= 0x001f01ff // FILE_ALL_ACCESS.
	}
	return result
}

// rootWritePermission describes metadata-reported permission to add a file
// at the share root. It never performs a write and cannot prove that a write
// would succeed (for example, disk quotas and read-only volumes also matter).
func rootWritePermission(shareMask uint32, shareKnown bool, rootMask uint32, rootKnown bool) (state, basis string) {
	switch {
	case shareKnown && rootKnown:
		basis = "share_and_root_metadata"
	case shareKnown:
		basis = "share_metadata"
	case rootKnown:
		basis = "root_metadata"
	default:
		return Unknown, "unavailable"
	}
	const addFile uint32 = 0x00000002
	shareMask = normalizeDirectoryAccess(shareMask)
	rootMask = normalizeDirectoryAccess(rootMask)
	if (shareKnown && shareMask&addFile == 0) || (rootKnown && rootMask&addFile == 0) {
		return Denied, basis
	}
	if shareKnown && rootKnown && (shareMask&rootMask)&addFile != 0 {
		return Allowed, basis
	}
	return Unknown, basis
}
