package smbwire

import (
	"bytes"
	"crypto/rc4"
	"encoding/binary"
	"strings"
	"testing"
)

// MS-NLMP 4.2.4: User/Domain/Password, server challenge 0123456789abcdef,
// client challenge aaaaaaaaaaaaaaaa, zero timestamp, and published AV pairs.
func TestNTLMv2PublishedVector(t *testing.T) {
	key := ntlmV2Key("User", "Password", "Domain")
	if !bytes.Equal(key, cryptoHex(t, "0c868a403bfd7a93a3001ef22ef02e3f")) {
		t.Fatalf("NTOWFv2: %x", key)
	}
	info := cryptoHex(t, "02000c0044006f006d00610069006e0001000c0053006500720076006500720000000000")
	lm, nt, base := ntlmV2Responses(key, cryptoHex(t, "0123456789abcdef"), bytes.Repeat([]byte{0xaa}, 8), make([]byte, 8), info)
	if !bytes.Equal(nt[:16], cryptoHex(t, "68cd0ab851e51c96aabc927bebef6a1c")) {
		t.Fatalf("NTLMv2 proof: %x", nt[:16])
	}
	if !bytes.Equal(lm, cryptoHex(t, "86c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa")) {
		t.Fatalf("LMv2 response: %x", lm)
	}
	if !bytes.Equal(base, cryptoHex(t, "8de40ccadbc14a82f15cb0ad0de95ca3")) {
		t.Fatalf("session base key: %x", base)
	}
	stream, _ := rc4.NewCipher(base)
	encryptedKey := make([]byte, 16)
	stream.XORKeyStream(encryptedKey, bytes.Repeat([]byte{0x55}, 16))
	if !bytes.Equal(encryptedKey, cryptoHex(t, "c5dad2544fc9799094ce1ce90bc9d03e")) {
		t.Fatalf("encrypted exported session key: %x", encryptedKey)
	}
}

func TestNTLMv2UnicodeIdentityVector(t *testing.T) {
	// Independently calculated with OpenSSL MD4 and Python HMAC-MD5 over
	// UTF-16LE("pässwörd🔐") and UTF-16LE("JÖSÉ😀Dömáin"). Only the username
	// is uppercased; domain spelling and supplementary characters are retained.
	want := cryptoHex(t, "463803ec5db8dd21ec11b3f2d875de57")
	if got := ntlmV2Key("jösé😀", "pässwörd🔐", "Dömáin"); !bytes.Equal(got, want) {
		t.Fatalf("Unicode NTOWFv2 = %x, want %x", got, want)
	}
}

func ntlmTestChallenge(flags uint32, timestamp bool) []byte {
	info := []byte{}
	if timestamp {
		info = append(info, 7, 0, 8, 0)
		info = append(info, make([]byte, 8)...)
	}
	info = append(info, 0, 0, 0, 0)
	message := make([]byte, 56)
	copy(message, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(message[8:12], 2)
	binary.LittleEndian.PutUint32(message[16:20], 56)
	binary.LittleEndian.PutUint32(message[20:24], flags)
	copy(message[24:32], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	binary.LittleEndian.PutUint16(message[40:42], uint16(len(info)))
	binary.LittleEndian.PutUint16(message[42:44], uint16(len(info)))
	binary.LittleEndian.PutUint32(message[44:48], 56)
	return append(message, info...)
}

func TestNTLMAuthenticationProofMICAndGuest(t *testing.T) {
	for _, guest := range []bool{false, true} {
		for _, version := range []bool{false, true} {
			flags := uint32(ntlmOffer)
			if !version {
				flags &^= ntlmVersion
			}
			negotiate := ntlmNegotiate()
			challenge := ntlmTestChallenge(flags, true)
			auth, exported, err := ntlmAuthenticate(negotiate, challenge, "User", "Password", "Domain", "server.example.com", guest)
			if err != nil {
				t.Fatal(err)
			}
			micOffset := 64
			if version {
				micOffset += 8
			}
			mic := append([]byte(nil), auth[micOffset:micOffset+16]...)
			withoutMIC := append([]byte(nil), auth...)
			clear(withoutMIC[micOffset : micOffset+16])
			if !bytes.Equal(mic, ntlmHMAC(exported, negotiate, challenge, withoutMIC)) {
				t.Fatal("Type3 MIC does not bind the full exchange")
			}
			user, _ := ntlmSecurityBuffer(auth, 36, micOffset+16)
			domain, _ := ntlmSecurityBuffer(auth, 28, micOffset+16)
			lm, _ := ntlmSecurityBuffer(auth, 12, micOffset+16)
			nt, _ := ntlmSecurityBuffer(auth, 20, micOffset+16)
			encKey, _ := ntlmSecurityBuffer(auth, 52, micOffset+16)
			if len(nt) <= 48 || len(lm) != 24 || !bytes.Equal(lm, make([]byte, 24)) || len(encKey) != 16 {
				t.Fatal("invalid response/key lengths or LMv2 sent despite timestamp")
			}
			responseKey := ntlmV2Key("User", "Password", "Domain")
			if guest {
				if len(user) != 0 || len(domain) != 0 {
					t.Fatal("guest sent supplied identity")
				}
				responseKey = ntlmV2Key("", "", "")
			} else if !bytes.Equal(user, utf16Bytes("User")) || !bytes.Equal(domain, utf16Bytes("Domain")) {
				t.Fatal("wrong credential identity")
			}
			if !bytes.Equal(nt[:16], ntlmHMAC(responseKey, challenge[24:32], nt[16:])) {
				t.Fatal("NTLMv2 proof does not match the selected identity")
			}
			base := ntlmHMAC(responseKey, nt[:16])
			stream, _ := rc4.NewCipher(base)
			decoded := make([]byte, 16)
			stream.XORKeyStream(decoded, encKey)
			if !bytes.Equal(decoded, exported) {
				t.Fatal("exported key exchange does not match proof")
			}
			if !bytes.Contains(nt, utf16Bytes("cifs/server.example.com")) || !bytes.Contains(nt, []byte{6, 0, 4, 0, 2, 0, 0, 0}) {
				t.Fatal("response lacks intended SPN/MIC-present AV flag")
			}
		}
	}
}

func TestNTLMWithoutKeyExchange(t *testing.T) {
	challenge := ntlmTestChallenge(ntlmOffer&^ntlmKeyExch, false)
	auth, exported, err := ntlmAuthenticate(ntlmNegotiate(), challenge, "User", "Password", "Domain", "server", false)
	if err != nil {
		t.Fatal(err)
	}
	nt, _ := ntlmSecurityBuffer(auth, 20, 88)
	lm, _ := ntlmSecurityBuffer(auth, 12, 88)
	encKey, _ := ntlmSecurityBuffer(auth, 52, 88)
	key := ntlmV2Key("User", "Password", "Domain")
	if len(encKey) != 0 || !bytes.Equal(exported, ntlmHMAC(key, nt[:16])) || bytes.Equal(lm, make([]byte, 24)) {
		t.Fatal("non-key-exchange authentication returned incorrect keys/responses")
	}
}

func TestNTLMAuthenticationUsesClientChannelBindings(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value []byte
	}{
		{"absent", nil},
		{"zero", make([]byte, 16)},
		{"peer_selected", bytes.Repeat([]byte{0xa5}, 16)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			challenge := ntlmTestChallenge(ntlmOffer, true)
			if tc.value != nil {
				challenge = append(challenge[:len(challenge)-4], 10, 0, 16, 0)
				challenge = append(challenge, tc.value...)
				challenge = append(challenge, 0, 0, 0, 0)
				binary.LittleEndian.PutUint16(challenge[40:42], uint16(len(challenge)-56))
				binary.LittleEndian.PutUint16(challenge[42:44], uint16(len(challenge)-56))
			}
			original := append([]byte(nil), challenge...)
			auth, _, err := ntlmAuthenticate(ntlmNegotiate(), challenge, "User", "Password", "Domain", "server", false)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(challenge, original) {
				t.Fatal("rewriting client bindings changed the challenge transcript")
			}
			response, err := ntlmSecurityBuffer(auth, 20, 88)
			if err != nil || len(response) < 48 {
				t.Fatalf("invalid NTLMv2 response: %x, %v", response, err)
			}
			// Skip NTProofStr and the fixed NTLMv2_CLIENT_CHALLENGE header;
			// inspect the AV pairs actually authenticated in the client proof.
			bindings := 0
			for pairs := response[44:]; ; {
				if len(pairs) < 4 {
					t.Fatal("missing AV terminator")
				}
				id, length := binary.LittleEndian.Uint16(pairs), int(binary.LittleEndian.Uint16(pairs[2:]))
				if length > len(pairs)-4 {
					t.Fatal("truncated AV pair")
				}
				if id == 0 {
					break
				}
				if id == 10 {
					bindings++
					if !bytes.Equal(pairs[4:4+length], make([]byte, 16)) {
						t.Fatalf("client authenticated peer-selected channel binding: %x", pairs[4:4+length])
					}
				}
				pairs = pairs[4+length:]
			}
			if bindings != 1 {
				t.Fatalf("client response contains %d channel-binding pairs, want one", bindings)
			}
		})
	}
}

func TestNTLMTargetInformationRejectsMalformedChannelBindings(t *testing.T) {
	for _, length := range []int{0, 15, 17} {
		info := []byte{10, 0, byte(length), 0}
		info = append(info, make([]byte, length)...)
		info = append(info, 0, 0, 0, 0)
		if _, _, _, err := ntlmTargetInformation(info, "server"); err == nil {
			t.Fatalf("accepted channel binding with length %d", length)
		}
	}
}

func TestNTLMRejectsMalformedChallenge(t *testing.T) {
	base := ntlmTestChallenge(ntlmOffer, true)
	for _, mutate := range []func([]byte){
		func(p []byte) { p[0] = 0 },
		func(p []byte) { p[8] = 3 },
		func(p []byte) { p[20] = 0 },
		func(p []byte) { binary.LittleEndian.PutUint32(p[44:48], 0xffffffff) },
		func(p []byte) { binary.LittleEndian.PutUint32(p[44:48], 1) },
		func(p []byte) { p[58] = 9 },
		func(p []byte) { p[len(p)-1] = 1 },
	} {
		challenge := append([]byte(nil), base...)
		mutate(challenge)
		if _, _, err := ntlmAuthenticate(ntlmNegotiate(), challenge, "User", "Password", "Domain", "host", false); err == nil {
			t.Fatal("accepted malformed challenge")
		}
	}
	for n := 0; n < 56; n++ {
		if _, _, err := ntlmAuthenticate(ntlmNegotiate(), base[:n], "User", "Password", "Domain", "host", false); err == nil {
			t.Fatal("accepted truncated challenge")
		}
	}
}

func TestNTLMChallengeIgnoresSecurityBufferAllocationSizes(t *testing.T) {
	for _, maximum := range []uint16{0, 1, 65535} {
		challenge := ntlmTestChallenge(ntlmOffer, true)
		name := utf16Bytes("LAB")
		binary.LittleEndian.PutUint16(challenge[12:14], uint16(len(name)))
		binary.LittleEndian.PutUint16(challenge[14:16], maximum)
		binary.LittleEndian.PutUint32(challenge[16:20], uint32(len(challenge)))
		challenge = append(challenge, name...)
		binary.LittleEndian.PutUint16(challenge[42:44], maximum)
		if _, _, err := ntlmAuthenticate(ntlmNegotiate(), challenge, "User", "Password", "LAB", "host", false); err != nil {
			t.Fatalf("MaxLen=%d rejected despite bounded payloads: %v", maximum, err)
		}
	}
}

func TestNTLMChallengeIgnoresUnnegotiatedFields(t *testing.T) {
	for _, disabled := range []uint32{ntlmTarget, ntlmTargetInfo, ntlmTarget | ntlmTargetInfo} {
		challenge := ntlmTestChallenge(ntlmOffer&^disabled, true)
		if disabled&ntlmTarget != 0 {
			copy(challenge[12:20], bytes.Repeat([]byte{0xff}, 8))
		}
		if disabled&ntlmTargetInfo != 0 {
			copy(challenge[40:48], bytes.Repeat([]byte{0xff}, 8))
		}
		auth, _, err := ntlmAuthenticate(ntlmNegotiate(), challenge, "User", "Password", "LAB", "host", false)
		if err != nil {
			t.Fatalf("unnegotiated fields %#x were interpreted: %v", disabled, err)
		}
		if disabled&ntlmTargetInfo != 0 {
			lm, err := ntlmSecurityBuffer(auth, 12, 88)
			if err != nil || len(lm) != 24 || bytes.Equal(lm, make([]byte, 24)) {
				t.Fatal("unnegotiated target information influenced the LM response")
			}
		}
	}
}

func TestNTLMChallengeRejectsMisalignedUnicodeTargetNames(t *testing.T) {
	for _, field := range []struct{ offset, size uint32 }{{73, 4}, {72, 3}} {
		challenge := append(ntlmTestChallenge(ntlmOffer, true), make([]byte, 8)...)
		binary.LittleEndian.PutUint16(challenge[12:14], uint16(field.size))
		binary.LittleEndian.PutUint32(challenge[16:20], field.offset)
		if _, _, err := ntlmAuthenticate(ntlmNegotiate(), challenge, "User", "Password", "LAB", "host", false); err == nil {
			t.Fatalf("accepted Unicode TargetName at offset %d with length %d", field.offset, field.size)
		}
	}
}

func TestNTLMSecurityBufferBoundsUseOnlyPayloadLength(t *testing.T) {
	for _, tt := range []struct {
		name    string
		length  uint16
		offset  uint32
		wantErr bool
	}{
		{"empty", 0, 0xffffffff, false},
		{"payload", 4, 8, false},
		{"overlaps_header", 4, 7, true},
		{"truncated_payload", 5, 8, true},
		{"out_of_bounds", 1, 0xffffffff, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			message := make([]byte, 12)
			binary.LittleEndian.PutUint16(message, tt.length)
			binary.LittleEndian.PutUint32(message[4:], tt.offset)
			data, err := ntlmSecurityBuffer(message, 0, 8)
			if (err != nil) != tt.wantErr || err == nil && len(data) != int(tt.length) {
				t.Fatalf("buffer length=%d, err=%v", len(data), err)
			}
		})
	}
}

func TestNTLMRejectsCombinedOversizedIdentity(t *testing.T) {
	// Each identity fits its own 16-bit security buffer, but the complete Type3
	// must also fit SESSION_SETUP's 16-bit security buffer after SPNEGO framing.
	identity := strings.Repeat("a", 17000)
	message, key, err := ntlmAuthenticate(ntlmNegotiate(), ntlmTestChallenge(ntlmOffer, true), identity, "password", identity, "host", false)
	if err == nil || message != nil || key != nil {
		t.Fatal("accepted an oversized combined authentication token")
	}
}

func TestNTLMMessageSignaturePublishedVector(t *testing.T) {
	// MS-NLMP 4.2.3.4, the extended-session-security MAC without key exchange.
	// Only the independent message-signature vector is used; authentication
	// remains NTLMv2-only.
	auth := make([]byte, 64)
	copy(auth, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(auth[8:], 3)
	binary.LittleEndian.PutUint32(auth[60:], ntlmESS|ntlmSign)
	got, err := ntlmMechListMIC(auth, cryptoHex(t, "eb93429a8bd952f8b89c55b87f475edc"), utf16Bytes("Plaintext"))
	if err != nil || !bytes.Equal(got, cryptoHex(t, "01000000ff2aeb52f681793a00000000")) {
		t.Fatalf("NTLM message MAC got %x, error %v", got, err)
	}
}

func TestNTLMMechListMIC(t *testing.T) {
	// Independently calculated using Python hashlib/HMAC and OpenSSL ARC4,
	// for the DER NTLM-only mechanism list and exported key 55 repeated 16x.
	mechList := cryptoHex(t, "300c060a2b06010401823702020a")
	key := bytes.Repeat([]byte{0x55}, 16)
	auth := make([]byte, 64)
	copy(auth, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(auth[8:], 3)
	for _, tc := range []struct {
		strength uint32
		client   string
		server   string
	}{
		{0x20000000, "0100000022a3984fefbb9c3200000000", "010000007dd6da05648a73ae00000000"},
		{0x80000000, "01000000489ec007bda3438d00000000", "01000000ed0635b9ef101fc900000000"},
		{0, "010000003afa859b310b000300000000", "01000000b148d65eba5b830b00000000"},
	} {
		binary.LittleEndian.PutUint32(auth[60:], ntlmESS|ntlmSign|ntlmKeyExch|tc.strength)
		got, err := ntlmMechListMIC(auth, key, mechList)
		if err != nil || !bytes.Equal(got, cryptoHex(t, tc.client)) {
			t.Fatalf("mechanism MIC strength %#x got %x, error %v", tc.strength, got, err)
		}
		server := cryptoHex(t, tc.server)
		if err := ntlmVerifyMechListMIC(auth, key, mechList, server); err != nil {
			t.Fatal(err)
		}
		if err := ntlmVerifyMechListMIC(auth, key, mechList, got); err == nil {
			t.Fatal("accepted reflected client mechanism-list MIC")
		}
		for i := range server {
			changed := append([]byte(nil), server...)
			changed[i] ^= 1
			if err := ntlmVerifyMechListMIC(auth, key, mechList, changed); err == nil {
				t.Fatal("accepted modified server mechanism-list MIC")
			}
		}
	}
	if _, err := ntlmMechListMIC(nil, key, mechList); err == nil {
		t.Fatal("accepted missing authentication token")
	}
	binary.LittleEndian.PutUint32(auth[60:], ntlmESS)
	if _, err := ntlmMechListMIC(auth, key, mechList); err == nil {
		t.Fatal("accepted missing integrity negotiation")
	}
}

func FuzzNTLMChallenge(f *testing.F) {
	f.Add(ntlmTestChallenge(ntlmOffer, true))
	f.Add([]byte("NTLMSSP\x00"))
	f.Fuzz(func(t *testing.T, challenge []byte) {
		_, _, _ = ntlmAuthenticate(ntlmNegotiate(), challenge, "fixture", "fixture-password", "LAB", "host", false)
	})
}
