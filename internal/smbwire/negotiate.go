package smbwire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	smb2IOCTL                  uint16 = 11
	fsctlValidateNegotiateInfo uint32 = 0x00140204
	statusInvalidDeviceRequest uint32 = 0xc0000010
	statusFileClosed           uint32 = 0xc0000128
)

// validateNegotiateInfo binds pre-3.1.1 negotiation to the authenticated
// session, once a tree exists. SMB3.1.1 already binds its transcript through
// preauthentication integrity. Guest and anonymous sessions have no signing
// key and cannot perform this validation.
// MS-SMB2 3.2.5.5 and 3.2.5.14.12:
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5b80eb31-7e0a-4f24-b570-15217d28f239
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/6a5bc90d-3c08-4498-905b-e7dab30b2e0e
func (c *Connection) validateNegotiateInfo(treeID uint32) error {
	if c.negotiationChecked || c.dialect == 0x311 || c.sessionFlags&3 != 0 {
		return nil
	}
	if !c.authenticated || len(c.clientNegotiateInfo) < 24 {
		return c.protocolError("SMB negotiation validation requires an authenticated negotiation")
	}
	body := make([]byte, 56, 56+len(c.clientNegotiateInfo))
	binary.LittleEndian.PutUint16(body, 57)
	binary.LittleEndian.PutUint32(body[4:], fsctlValidateNegotiateInfo)
	for i := 8; i < 24; i++ {
		body[i] = 0xff // Connection-level control, without opening a file.
	}
	binary.LittleEndian.PutUint32(body[24:], 120)
	binary.LittleEndian.PutUint32(body[28:], uint32(len(c.clientNegotiateInfo)))
	binary.LittleEndian.PutUint32(body[36:], 120)
	binary.LittleEndian.PutUint32(body[44:], uint32(len(c.serverNegotiateInfo)))
	binary.LittleEndian.PutUint32(body[48:], 1) // SMB2_0_IOCTL_IS_FSCTL.
	body = append(body, c.clientNegotiateInfo...)
	r, err := c.exchange(smb2IOCTL, treeID, body)
	if err != nil {
		if status, ok := errors.AsType[*NTStatusError](err); ok {
			// SMB2-only servers may not implement this control. Accept only
			// authenticated unsupported outcomes documented by MS-SMB2
			// 3.3.5.15 (including its Windows behavior note 382). Our policy
			// requires successful validation from servers negotiating SMB3.
			if c.dialect < 0x300 && (status.Status == StatusNotSupported || status.Status == statusInvalidDeviceRequest || status.Status == statusFileClosed) {
				c.negotiationChecked = true
				return nil
			}
			// A control failure is not a share-permission denial, even when
			// its NT status is ACCESS_DENIED. Do not expose it as one.
			return c.protocolError(fmt.Sprintf("SMB negotiation validation failed: %v", err))
		}
		c.Close()
		return fmt.Errorf("SMB negotiation validation failed: %w", err)
	}
	if len(r) < 112 || binary.LittleEndian.Uint16(r[64:]) != 49 || binary.LittleEndian.Uint32(r[68:]) != fsctlValidateNegotiateInfo ||
		binary.LittleEndian.Uint64(r[72:]) != ^uint64(0) || binary.LittleEndian.Uint64(r[80:]) != ^uint64(0) ||
		binary.LittleEndian.Uint32(r[92:]) != 0 || binary.LittleEndian.Uint32(r[100:]) != uint32(len(c.serverNegotiateInfo)) {
		return c.protocolError("invalid SMB negotiation validation response")
	}
	offset := uint64(binary.LittleEndian.Uint32(r[96:]))
	info, err := boundedField(r, offset, uint64(len(c.serverNegotiateInfo)), 112)
	if err != nil || offset%8 != 0 || !bytes.Equal(info, c.serverNegotiateInfo[:]) {
		return c.protocolError("SMB negotiation validation response does not match the original negotiation")
	}
	c.negotiationChecked = true
	return nil
}
