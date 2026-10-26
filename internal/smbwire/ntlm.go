package smbwire

// The NTLMv2 subset implemented here follows MS-NLMP 2.2.1, 2.2.2.1,
// 3.1.5.1.2 and 3.3.2. It intentionally has no NTLMv1 or null-session path.
import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/md4"
)

const (
	ntlmUnicode    uint32 = 0x00000001
	ntlmTarget     uint32 = 0x00000004
	ntlmSign       uint32 = 0x00000010
	ntlmSeal       uint32 = 0x00000020
	ntlmNTLM       uint32 = 0x00000200
	ntlmESS        uint32 = 0x00080000
	ntlmTargetInfo uint32 = 0x00800000
	ntlmVersion    uint32 = 0x02000000
	ntlmKeyExch    uint32 = 0x40000000
	ntlmOffer             = ntlmUnicode | ntlmTarget | ntlmSign | ntlmSeal | ntlmNTLM | 0x00008000 | ntlmESS | ntlmTargetInfo | ntlmVersion | 0x20000000 | ntlmKeyExch | 0x80000000
)

var ntlmClientVersion = [8]byte{10, 0, 0, 0, 0, 0, 0, 15}

func ntlmNegotiate() []byte {
	message := make([]byte, 40)
	copy(message, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(message[8:12], 1)
	binary.LittleEndian.PutUint32(message[12:16], ntlmOffer)
	// Empty domain/workstation security buffers point after the fixed header.
	binary.LittleEndian.PutUint32(message[20:24], 40)
	binary.LittleEndian.PutUint32(message[28:32], 40)
	copy(message[32:40], ntlmClientVersion[:])
	return message
}

func ntlmAuthenticate(negotiate, challenge []byte, user, password, domain, host string, guest bool) (message, sessionKey []byte, err error) {
	bad := errors.New("invalid NTLM challenge")
	if len(negotiate) < 32 || string(negotiate[:8]) != "NTLMSSP\x00" || binary.LittleEndian.Uint32(negotiate[8:12]) != 1 {
		return nil, nil, errors.New("invalid NTLM negotiation message")
	}
	if len(challenge) < 48 || len(challenge) > 1<<20 || string(challenge[:8]) != "NTLMSSP\x00" || binary.LittleEndian.Uint32(challenge[8:12]) != 2 {
		return nil, nil, bad
	}
	serverFlags := binary.LittleEndian.Uint32(challenge[20:24])
	flags := serverFlags & binary.LittleEndian.Uint32(negotiate[12:16]) & ntlmOffer
	if flags&(ntlmUnicode|ntlmNTLM|ntlmESS) != ntlmUnicode|ntlmNTLM|ntlmESS {
		return nil, nil, errors.New("server does not support required NTLMv2 negotiation flags")
	}
	minimum := 48
	if serverFlags&ntlmVersion != 0 {
		minimum = 56
		if len(challenge) < minimum {
			return nil, nil, bad
		}
	}
	// MS-NLMP 2.2.1.2 requires unnegotiated fields to be ignored. Bound
	// negotiated payloads, including TargetName even though we do not use it.
	if serverFlags&ntlmTarget != 0 {
		name, err := ntlmSecurityBuffer(challenge, 12, minimum)
		if err != nil || len(name)%2 != 0 || len(name) != 0 && binary.LittleEndian.Uint32(challenge[16:20])%2 != 0 {
			return nil, nil, bad
		}
	}
	var info []byte
	if serverFlags&ntlmTargetInfo != 0 {
		info, err = ntlmSecurityBuffer(challenge, 40, minimum)
		if err != nil {
			return nil, nil, bad
		}
	}
	if guest {
		// A deliberately computed proof for the empty identity is distinct from
		// an anonymous Type3 with empty challenge-response fields. The final SMB
		// session flags still determine whether the server granted Guest.
		user, password, domain = "", "", ""
	} else if user == "" {
		return nil, nil, errors.New("NTLM username is required")
	}
	if !utf8.ValidString(user) || !utf8.ValidString(password) || !utf8.ValidString(domain) || !utf8.ValidString(host) {
		return nil, nil, errors.New("NTLM credentials and target must be valid UTF-8")
	}
	userBytes, domainBytes := utf16Bytes(user), utf16Bytes(domain)
	if len(userBytes) > 65535 || len(domainBytes) > 65535 || len(utf16Bytes(host)) > 65000 {
		return nil, nil, errors.New("NTLM identity or target is too long")
	}
	info, timestamp, serverTimestamp, err := ntlmTargetInformation(info, host)
	if err != nil {
		return nil, nil, err
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, nil, err
	}
	responseKey := ntlmV2Key(user, password, domain)
	lm, nt, baseKey := ntlmV2Responses(responseKey, challenge[24:32], nonce[:], timestamp[:], info)
	if serverTimestamp {
		clear(lm) // MS-NLMP 3.1.5.1.2: do not send LMv2 with a server timestamp.
	}
	if len(nt) > 65535 {
		return nil, nil, errors.New("NTLM target information is too long")
	}
	var encryptedKey []byte
	sessionKey = append([]byte(nil), baseKey...)
	if flags&ntlmKeyExch != 0 && flags&(ntlmSign|ntlmSeal) != 0 {
		if _, err := rand.Read(sessionKey); err != nil {
			return nil, nil, err
		}
		stream, err := rc4.NewCipher(baseKey)
		if err != nil {
			return nil, nil, err
		}
		encryptedKey = make([]byte, 16)
		stream.XORKeyStream(encryptedKey, sessionKey)
	} else {
		flags &^= ntlmKeyExch
	}
	// We always provide a MIC and set MsvAvFlags.MIC_PRESENT in the AV pairs.
	micOffset := 64
	if flags&ntlmVersion != 0 {
		micOffset += 8
	}
	// SESSION_SETUP's SecurityBufferLength is 16 bits and SPNEGO adds framing.
	// Bound the whole token, not only its individual 16-bit security buffers.
	messageSize := micOffset + 16 + len(domainBytes) + len(userBytes) + len(lm) + len(nt) + len(encryptedKey)
	if messageSize > 65000 {
		return nil, nil, errors.New("NTLM authentication token is too long")
	}
	message = make([]byte, micOffset+16, messageSize)
	copy(message, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(message[8:12], 3)
	binary.LittleEndian.PutUint32(message[60:64], flags)
	if flags&ntlmVersion != 0 {
		copy(message[64:72], ntlmClientVersion[:])
	}
	for _, field := range []struct {
		offset int
		value  []byte
	}{{28, domainBytes}, {36, userBytes}, {44, nil}, {12, lm}, {20, nt}, {52, encryptedKey}} {
		binary.LittleEndian.PutUint16(message[field.offset:field.offset+2], uint16(len(field.value)))
		binary.LittleEndian.PutUint16(message[field.offset+2:field.offset+4], uint16(len(field.value)))
		binary.LittleEndian.PutUint32(message[field.offset+4:field.offset+8], uint32(len(message)))
		message = append(message, field.value...)
	}
	mic := ntlmHMAC(sessionKey, negotiate, challenge, message)
	copy(message[micOffset:micOffset+16], mic)
	return message, sessionKey, nil
}

func ntlmSecurityBuffer(message []byte, offset, minimum int) ([]byte, error) {
	if offset < 0 || offset > len(message)-8 {
		return nil, errors.New("invalid NTLM security buffer")
	}
	n := uint64(binary.LittleEndian.Uint16(message[offset : offset+2]))
	// MaxLen describes the sender's allocation and MUST be ignored on receipt.
	// With no payload, BufferOffset also has no bytes to address.
	if n == 0 {
		return nil, nil
	}
	start := uint64(binary.LittleEndian.Uint32(message[offset+4 : offset+8]))
	if start > uint64(len(message)) || n > uint64(len(message))-start || start < uint64(minimum) {
		return nil, errors.New("invalid NTLM security buffer bounds")
	}
	return message[int(start):int(start+n)], nil
}

func ntlmHMAC(key []byte, parts ...[]byte) []byte {
	h := hmac.New(md5.New, key)
	for _, part := range parts {
		h.Write(part)
	}
	return h.Sum(nil)
}

func ntlmV2Key(user, password, domain string) []byte {
	h := md4.New()
	h.Write(utf16Bytes(password))
	return ntlmHMAC(h.Sum(nil), utf16Bytes(strings.ToUpper(user)+domain))
}

func ntlmV2Responses(key, serverChallenge, nonce, timestamp, info []byte) (lm, nt, baseKey []byte) {
	blob := make([]byte, 28, 28+len(info)+4)
	blob[0], blob[1] = 1, 1
	copy(blob[8:16], timestamp)
	copy(blob[16:24], nonce)
	blob = append(blob, info...)
	blob = append(blob, 0, 0, 0, 0)
	proof := ntlmHMAC(key, serverChallenge, blob)
	nt = append(proof, blob...)
	lm = append(ntlmHMAC(key, serverChallenge, nonce), nonce...)
	baseKey = ntlmHMAC(key, proof)
	return
}

// ntlmMechListMIC signs the DER MechTypeList from the initial SPNEGO token.
// This is NTLM's sequence-zero message signature (MS-NLMP 3.4.4.2/3.4.5),
// distinct from the Type3 transcript MIC. SPNEGO uses a fresh RC4 state for
// this signature, without consuming application message state (MS-SPNG 3.2.5.1).
func ntlmMechListMIC(auth, sessionKey, mechList []byte) ([]byte, error) {
	return ntlmMechListSignature(auth, sessionKey, mechList, true)
}

func ntlmVerifyMechListMIC(auth, sessionKey, mechList, mic []byte) error {
	want, err := ntlmMechListSignature(auth, sessionKey, mechList, false)
	if err != nil {
		return err
	}
	if !hmac.Equal(want, mic) {
		return errors.New("invalid SPNEGO mechanism-list MIC")
	}
	return nil
}

func ntlmMechListSignature(auth, sessionKey, mechList []byte, client bool) ([]byte, error) {
	if len(auth) < 64 || string(auth[:8]) != "NTLMSSP\x00" || binary.LittleEndian.Uint32(auth[8:12]) != 3 || len(sessionKey) != 16 || len(mechList) == 0 || len(mechList) > 65535 {
		return nil, errors.New("invalid NTLM mechanism-list signing input")
	}
	flags := binary.LittleEndian.Uint32(auth[60:64])
	if flags&ntlmESS == 0 || flags&(ntlmSign|ntlmSeal) == 0 {
		return nil, errors.New("NTLM mechanism-list MIC requires session integrity")
	}
	direction := "client-to-server"
	if !client {
		direction = "server-to-client"
	}
	signingMaterial := append(append([]byte(nil), sessionKey...), "session key to "+direction+" signing key magic constant\x00"...)
	signingKey := md5.Sum(signingMaterial)
	checksum := ntlmHMAC(signingKey[:], []byte{0, 0, 0, 0}, mechList)[:8]
	if flags&ntlmKeyExch != 0 {
		sealKeySize := 5
		if flags&0x20000000 != 0 {
			sealKeySize = 16
		} else if flags&0x80000000 != 0 {
			sealKeySize = 7
		}
		sealingMaterial := append(append([]byte(nil), sessionKey[:sealKeySize]...), "session key to "+direction+" sealing key magic constant\x00"...)
		sealingKey := md5.Sum(sealingMaterial)
		stream, err := rc4.NewCipher(sealingKey[:])
		if err != nil {
			return nil, err
		}
		stream.XORKeyStream(checksum, checksum)
	}
	mic := make([]byte, 16)
	binary.LittleEndian.PutUint32(mic, 1)
	copy(mic[4:12], checksum)
	return mic, nil
}

func ntlmTargetInformation(info []byte, host string) (out []byte, timestamp [8]byte, hasTimestamp bool, err error) {
	bad := errors.New("invalid NTLM target information")
	var flags uint32
	seen := make(map[uint16]bool)
	terminated := len(info) == 0
	for offset, count := 0, 0; offset < len(info); count++ {
		if count >= 256 || len(info)-offset < 4 {
			return nil, timestamp, false, bad
		}
		id := binary.LittleEndian.Uint16(info[offset : offset+2])
		n := int(binary.LittleEndian.Uint16(info[offset+2 : offset+4]))
		start := offset + 4
		if n > len(info)-start || seen[id] {
			return nil, timestamp, false, bad
		}
		seen[id] = true
		value := info[start : start+n]
		if id == 0 {
			if n != 0 || start != len(info) {
				return nil, timestamp, false, bad
			}
			terminated = true
			break
		}
		switch id {
		case 1, 2, 3, 4, 5, 9:
			if n%2 != 0 {
				return nil, timestamp, false, bad
			}
		case 6:
			if n != 4 {
				return nil, timestamp, false, bad
			}
			flags = binary.LittleEndian.Uint32(value)
		case 7:
			if n != 8 {
				return nil, timestamp, false, bad
			}
			copy(timestamp[:], value)
			hasTimestamp = true
		case 10:
			if n != 16 {
				return nil, timestamp, false, bad
			}
		}
		// Replace client-owned fields rather than authenticating a binding
		// chosen by the peer. This SMB transport has no TLS channel binding.
		if id != 6 && id != 10 && (id != 9 || host == "") {
			out = append(out, info[offset:start+n]...)
		}
		offset = start + n
	}
	if !terminated {
		return nil, timestamp, false, bad
	}
	if !hasTimestamp {
		const epochDifference = uint64(11644473600)
		now := time.Now()
		filetime := (uint64(now.Unix())+epochDifference)*10000000 + uint64(now.Nanosecond()/100)
		binary.LittleEndian.PutUint64(timestamp[:], filetime)
	}
	var micFlags [8]byte
	binary.LittleEndian.PutUint16(micFlags[:2], 6)
	binary.LittleEndian.PutUint16(micFlags[2:4], 4)
	binary.LittleEndian.PutUint32(micFlags[4:8], flags|2)
	out = append(out, micFlags[:]...)
	// MS-NLMP 3.1.5.1.2: absent client channel bindings are represented by
	// sixteen zero bytes, even if the challenge supplied a different hash.
	var channelBindings [20]byte
	binary.LittleEndian.PutUint16(channelBindings[:2], 10)
	binary.LittleEndian.PutUint16(channelBindings[2:4], 16)
	out = append(out, channelBindings[:]...)
	if host != "" {
		spn := utf16Bytes("cifs/" + host)
		if len(spn) > 65535 {
			return nil, timestamp, false, errors.New("NTLM service name is too long")
		}
		var header [4]byte
		binary.LittleEndian.PutUint16(header[:2], 9)
		binary.LittleEndian.PutUint16(header[2:4], uint16(len(spn)))
		out = append(out, header[:]...)
		out = append(out, spn...)
	}
	out = append(out, 0, 0, 0, 0)
	return out, timestamp, hasTimestamp, nil
}
