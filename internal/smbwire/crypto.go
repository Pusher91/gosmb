package smbwire

// These narrow SMB cryptographic operations follow MS-SMB2 3.1.4, NIST
// SP800-108 counter-mode KDF, RFC 4493 (CMAC), and RFC 3610 (CCM).
import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

const cryptoMaxMessage = 16 << 20

func deriveKeys(dialect uint16, sessionKey, preauth []byte) (sign, encrypt, decrypt []byte, err error) {
	if len(sessionKey) != 16 {
		return nil, nil, nil, errors.New("SMB requires a 16-byte session key")
	}
	switch dialect {
	case 0x0202, 0x0210:
		return append([]byte(nil), sessionKey...), nil, nil, nil
	case 0x0300, 0x0302:
		return smbKDF(sessionKey, "SMB2AESCMAC\x00", []byte("SmbSign\x00")),
			smbKDF(sessionKey, "SMB2AESCCM\x00", []byte("ServerIn \x00")),
			smbKDF(sessionKey, "SMB2AESCCM\x00", []byte("ServerOut\x00")), nil
	case 0x0311:
		if len(preauth) != 64 {
			return nil, nil, nil, errors.New("SMB 3.1.1 requires a 64-byte preauthentication hash")
		}
		return smbKDF(sessionKey, "SMBSigningKey\x00", preauth),
			smbKDF(sessionKey, "SMBC2SCipherKey\x00", preauth),
			smbKDF(sessionKey, "SMBS2CCipherKey\x00", preauth), nil
	default:
		return nil, nil, nil, errors.New("unsupported SMB dialect for key derivation")
	}
}

// MS-SMB2 includes the terminating NUL in label/context strings. The KDF
// inserts its own separator after the complete label, as SP800-108 specifies.
func smbKDF(key []byte, label string, context []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte{0, 0, 0, 1})
	h.Write([]byte(label))
	h.Write([]byte{0})
	h.Write(context)
	h.Write([]byte{0, 0, 0, 128})
	return h.Sum(nil)[:16]
}

// The caller sets SMB2_FLAGS_SIGNED and zeroes the signature field first.
func signSMB(dialect uint16, key, message []byte) ([]byte, error) {
	if len(key) != 16 || len(message) < 64 || len(message) > cryptoMaxMessage {
		return nil, errors.New("invalid SMB signing input")
	}
	switch dialect {
	case 0x0202, 0x0210:
		h := hmac.New(sha256.New, key)
		h.Write(message)
		return h.Sum(nil)[:16], nil
	case 0x0300, 0x0302, 0x0311:
		return aesCMAC(key, message)
	default:
		return nil, errors.New("unsupported SMB signing dialect")
	}
}

func aesCMAC(key, message []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	var zero, l [16]byte
	block.Encrypt(l[:], zero[:])
	k1 := cmacDouble(l)
	k2 := cmacDouble(k1)
	var state [16]byte
	for len(message) > 16 {
		for i := range state {
			state[i] ^= message[i]
		}
		block.Encrypt(state[:], state[:])
		message = message[16:]
	}
	var last [16]byte
	copy(last[:], message)
	if len(message) == 16 {
		for i := range last {
			last[i] ^= k1[i]
		}
	} else {
		last[len(message)] = 0x80
		for i := range last {
			last[i] ^= k2[i]
		}
	}
	for i := range state {
		state[i] ^= last[i]
	}
	block.Encrypt(state[:], state[:])
	return append([]byte(nil), state[:]...), nil
}

func cmacDouble(x [16]byte) (out [16]byte) {
	var carry byte
	for i := len(x) - 1; i >= 0; i-- {
		out[i] = x[i]<<1 | carry
		carry = x[i] >> 7
	}
	// Reduction by the CMAC polynomial, without a branch on key material.
	out[15] ^= 0x87 & (byte(0) - carry)
	return
}

func encryptSMB(dialect uint16, key []byte, sessionID uint64, message []byte) ([]byte, error) {
	if len(key) != 16 || len(message) < 64 || len(message) > cryptoMaxMessage {
		return nil, errors.New("invalid SMB encryption input")
	}
	nonceLen := 11
	if dialect == 0x0311 {
		nonceLen = 12
	} else if dialect != 0x0300 && dialect != 0x0302 {
		return nil, errors.New("unsupported SMB encryption dialect")
	}
	// Reserve the complete transform and the AEAD's trailing tag so GCM can
	// seal directly into the output buffer. The tag moves into the header.
	header := make([]byte, 52, 52+len(message)+16)
	copy(header, "\xfdSMB")
	if _, err := rand.Read(header[20 : 20+nonceLen]); err != nil {
		return nil, err
	}
	binary.LittleEndian.PutUint32(header[36:40], uint32(len(message)))
	binary.LittleEndian.PutUint16(header[42:44], 1)
	binary.LittleEndian.PutUint64(header[44:52], sessionID)
	var sealed []byte
	var err error
	if dialect == 0x0311 {
		block, _ := aes.NewCipher(key)
		var gcm cipher.AEAD
		gcm, err = cipher.NewGCM(block)
		if err == nil {
			sealed = gcm.Seal(header[52:], header[20:32], message, header[20:52])
		}
	} else {
		sealed, err = ccmSeal(key, header[20:31], message, header[20:52], 16)
	}
	if err != nil {
		return nil, err
	}
	copy(header[4:20], sealed[len(sealed)-16:])
	return append(header, sealed[:len(sealed)-16]...), nil
}

func decryptSMB(dialect uint16, key []byte, sessionID uint64, frame []byte) ([]byte, error) {
	bad := errors.New("invalid encrypted SMB message")
	if len(key) != 16 || len(frame) < 52+64 || len(frame) > 52+cryptoMaxMessage || string(frame[:4]) != "\xfdSMB" {
		return nil, bad
	}
	if binary.LittleEndian.Uint64(frame[44:52]) != sessionID || binary.LittleEndian.Uint16(frame[40:42]) != 0 || binary.LittleEndian.Uint16(frame[42:44]) != 1 || uint64(binary.LittleEndian.Uint32(frame[36:40])) != uint64(len(frame)-52) {
		return nil, bad
	}
	sealed := make([]byte, 0, len(frame)-52+16)
	sealed = append(sealed, frame[52:]...)
	sealed = append(sealed, frame[4:20]...)
	var plain []byte
	var err error
	switch dialect {
	case 0x0311:
		block, _ := aes.NewCipher(key)
		gcm, e := cipher.NewGCM(block)
		if e != nil {
			return nil, e
		}
		// This private copy can hold the plaintext without modifying frame.
		plain, err = gcm.Open(sealed[:0], frame[20:32], sealed, frame[20:52])
	case 0x0300, 0x0302:
		plain, err = ccmOpen(key, frame[20:31], sealed, frame[20:52], 16)
	default:
		return nil, errors.New("unsupported SMB encryption dialect")
	}
	if err != nil {
		return nil, errors.New("SMB encryption authentication failed")
	}
	return plain, nil
}

// CCM returns ciphertext followed by its authentication tag, like cipher.AEAD.
// The generic nonce/tag parameters permit the published RFC 3610 vectors;
// SMB always calls it with an 11-byte nonce and a 16-byte tag.
func ccmSeal(key, nonce, plaintext, aad []byte, tagLen int) ([]byte, error) {
	block, err := ccmValidate(key, nonce, len(plaintext), len(aad), tagLen)
	if err != nil {
		return nil, err
	}
	tag := ccmMAC(block, nonce, plaintext, aad, tagLen)
	out := make([]byte, len(plaintext)+tagLen)
	ccmCTR(block, nonce, out[:len(plaintext)], plaintext, 1)
	ccmCTR(block, nonce, out[len(plaintext):], tag[:tagLen], 0)
	return out, nil
}

func ccmOpen(key, nonce, ciphertext, aad []byte, tagLen int) ([]byte, error) {
	if tagLen < 4 || len(ciphertext) < tagLen {
		return nil, errors.New("invalid CCM ciphertext")
	}
	size := len(ciphertext) - tagLen
	block, err := ccmValidate(key, nonce, size, len(aad), tagLen)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, size)
	ccmCTR(block, nonce, plaintext, ciphertext[:size], 1)
	tag := ccmMAC(block, nonce, plaintext, aad, tagLen)
	var encryptedTag [16]byte
	ccmCTR(block, nonce, encryptedTag[:tagLen], tag[:tagLen], 0)
	if subtle.ConstantTimeCompare(encryptedTag[:tagLen], ciphertext[size:]) != 1 {
		clear(plaintext)
		return nil, errors.New("CCM authentication failed")
	}
	return plaintext, nil
}

func ccmValidate(key, nonce []byte, size, aadSize, tagLen int) (cipher.Block, error) {
	if len(key) != 16 || len(nonce) < 7 || len(nonce) > 13 || tagLen < 4 || tagLen > 16 || tagLen%2 != 0 || size < 0 || size > cryptoMaxMessage || aadSize > cryptoMaxMessage {
		return nil, errors.New("invalid CCM parameters")
	}
	q := 15 - len(nonce)
	if q < 8 && uint64(size) >= uint64(1)<<(8*q) {
		return nil, errors.New("CCM message exceeds nonce capacity")
	}
	return aes.NewCipher(key)
}

func ccmMAC(block cipher.Block, nonce, plaintext, aad []byte, tagLen int) [16]byte {
	q := 15 - len(nonce)
	var state [16]byte
	state[0] = byte((tagLen-2)/2)<<3 | byte(q-1)
	if len(aad) > 0 {
		state[0] |= 0x40
	}
	copy(state[1:], nonce)
	putCCMLength(state[16-q:], uint64(len(plaintext)))
	block.Encrypt(state[:], state[:])
	process := func(data []byte) {
		for len(data) > 0 {
			n := min(len(data), 16)
			for i := 0; i < n; i++ {
				state[i] ^= data[i]
			}
			block.Encrypt(state[:], state[:])
			data = data[n:]
		}
	}
	if len(aad) > 0 {
		var first [16]byte
		prefixLen := 2
		if len(aad) < 0xff00 {
			binary.BigEndian.PutUint16(first[:2], uint16(len(aad)))
		} else {
			first[0], first[1] = 0xff, 0xfe
			binary.BigEndian.PutUint32(first[2:6], uint32(len(aad)))
			prefixLen = 6
		}
		n := copy(first[prefixLen:], aad)
		process(first[:])
		process(aad[n:])
	}
	process(plaintext)
	return state
}

func putCCMLength(dst []byte, n uint64) {
	for i := len(dst) - 1; i >= 0; i-- {
		dst[i] = byte(n)
		n >>= 8
	}
}

func ccmCTR(block cipher.Block, nonce, dst, src []byte, counter uint64) {
	q := 15 - len(nonce)
	var input, stream [16]byte
	input[0] = byte(q - 1)
	copy(input[1:], nonce)
	for len(src) > 0 {
		putCCMLength(input[16-q:], counter)
		block.Encrypt(stream[:], input[:])
		n := min(len(src), 16)
		for i := 0; i < n; i++ {
			dst[i] = src[i] ^ stream[i]
		}
		src, dst = src[n:], dst[n:]
		counter++
	}
}
