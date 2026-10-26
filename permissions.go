package main

import (
	"encoding/binary"
	"errors"
	"fmt"
)

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
			if status != 0 {
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
	// FILE_ADD_FILE, GENERIC_WRITE, and GENERIC_ALL each grant adding a file.
	// Evaluate each ACL layer separately: they may use different generic bits.
	const addFileRights uint32 = 0x00000002 | 0x40000000 | 0x10000000
	if (shareKnown && shareMask&addFileRights == 0) || (rootKnown && rootMask&addFileRights == 0) {
		return Denied, basis
	}
	if shareKnown && rootKnown {
		return Allowed, basis
	}
	return Unknown, basis
}
