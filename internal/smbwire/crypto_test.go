package smbwire

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func cryptoHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Published known-answer examples from RFC 4493 section 4.
func TestCMACKnownAnswers(t *testing.T) {
	key := cryptoHex(t, "2b7e151628aed2a6abf7158809cf4f3c")
	full := cryptoHex(t, "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
	for _, tc := range []struct {
		n    int
		want string
	}{{0, "bb1d6929e95937287fa37d129b756746"}, {16, "070a16b46b4d4144f79bdd9dd04a287c"}, {40, "dfa66747de9ae63030ca32611497c827"}, {64, "51f0bebf7e3b9d92fc49741779363cfe"}} {
		got, err := aesCMAC(key, full[:tc.n])
		if err != nil || !bytes.Equal(got, cryptoHex(t, tc.want)) {
			t.Errorf("CMAC length %d: got %x, error %v", tc.n, got, err)
		}
	}
}

// Packet vector 1 in RFC 3610 section 8. Expected ciphertext includes the tag.
func TestCCMKnownAnswer(t *testing.T) {
	key := cryptoHex(t, "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf")
	nonce := cryptoHex(t, "00000003020100a0a1a2a3a4a5")
	aad := cryptoHex(t, "0001020304050607")
	plain := cryptoHex(t, "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e")
	want := cryptoHex(t, "588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0")
	got, err := ccmSeal(key, nonce, plain, aad, 8)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("CCM vector got %x, error %v", got, err)
	}
	opened, err := ccmOpen(key, nonce, want, aad, 8)
	if err != nil || !bytes.Equal(opened, plain) {
		t.Fatalf("CCM open vector got %x, error %v", opened, err)
	}
	for i := range want {
		changed := append([]byte(nil), want...)
		changed[i] ^= 1
		if result, err := ccmOpen(key, nonce, changed, aad, 8); err == nil || result != nil {
			t.Fatalf("accepted modified CCM byte %d", i)
		}
	}
}

// Independent AESCCM output for SMB's 11-byte nonce and 16-byte tag, generated
// with Python cryptography's OpenSSL-backed AESCCM primitive.
func TestCCMSMBParametersKnownAnswer(t *testing.T) {
	key, nonce, aad, plain := make([]byte, 16), make([]byte, 11), make([]byte, 32), make([]byte, 33)
	for _, p := range [][]byte{key, nonce, aad, plain} {
		for i := range p {
			p[i] = byte(i)
		}
	}
	want := cryptoHex(t, "3f9d27a8d24d377bc99102839785c46452e44653e5f3f27e8d45397d62f227721a67fd56105a1f01aa22ebb54e093b0333")
	got, err := ccmSeal(key, nonce, plain, aad, 16)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("CCM SMB-parameter vector got %x, error %v", got, err)
	}
}

func TestCCMBoundaries(t *testing.T) {
	key, nonce := make([]byte, 16), make([]byte, 11)
	for _, n := range []int{0, 1, 15, 16, 17, 63, 64, 65} {
		for _, aadSize := range []int{0, 1, 14, 15, 16, 17, 32, 0xfeff, 0xff00} {
			plain, aad := bytes.Repeat([]byte{0xab}, n), bytes.Repeat([]byte{0xcd}, aadSize)
			sealed, err := ccmSeal(key, nonce, plain, aad, 16)
			if err != nil {
				t.Fatal(err)
			}
			opened, err := ccmOpen(key, nonce, sealed, aad, 16)
			if err != nil || !bytes.Equal(plain, opened) {
				t.Fatalf("CCM size %d AAD %d roundtrip: %v", n, aadSize, err)
			}
		}
	}
	if _, err := ccmSeal(key, make([]byte, 13), make([]byte, 1<<16), nil, 16); err == nil {
		t.Fatal("CCM accepted a length that overflows the nonce capacity")
	}
}

func TestSMBTransformRoundtripAndTamper(t *testing.T) {
	key := cryptoHex(t, "00112233445566778899aabbccddeeff")
	plain := append([]byte("\xfeSMB"), bytes.Repeat([]byte{0x5a}, 93)...)
	for _, dialect := range []uint16{0x0300, 0x0302, 0x0311} {
		frame, err := encryptSMB(dialect, key, 123, plain)
		if err != nil {
			t.Fatal(err)
		}
		opened, err := decryptSMB(dialect, key, 123, frame)
		if err != nil || !bytes.Equal(opened, plain) {
			t.Fatalf("dialect %#x roundtrip failed: %v", dialect, err)
		}
		for i := range frame {
			changed := append([]byte(nil), frame...)
			changed[i] ^= 1
			if result, err := decryptSMB(dialect, key, 123, changed); err == nil || result != nil {
				t.Fatalf("dialect %#x accepted transform tamper at %d", dialect, i)
			}
		}
		if _, err := decryptSMB(dialect, key, 456, frame); err == nil {
			t.Fatal("accepted another session's encrypted frame")
		}
		for n := 0; n < 52+64; n++ {
			if _, err := decryptSMB(dialect, key, 123, frame[:n]); err == nil {
				t.Fatal("accepted truncated transform")
			}
		}
	}
}

func TestSMBTransformPreservesInputBuffers(t *testing.T) {
	key := make([]byte, 16)
	for _, dialect := range []uint16{0x0300, 0x0302, 0x0311} {
		for _, size := range []int{64, 65, 4096, 65536} {
			plain := bytes.Repeat([]byte{0x5a}, size)
			original := bytes.Clone(plain)
			frame, err := encryptSMB(dialect, key, 123, plain)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(plain, original) {
				t.Fatalf("dialect %#x encryption modified its input at size %d", dialect, size)
			}
			originalFrame := bytes.Clone(frame)
			opened, err := decryptSMB(dialect, key, 123, frame)
			if err != nil || !bytes.Equal(opened, plain) {
				t.Fatalf("dialect %#x roundtrip at size %d: %v", dialect, size, err)
			}
			// The returned plaintext must own its buffer, including when the
			// AEAD decrypts in place into an internal working buffer.
			clear(opened)
			if !bytes.Equal(frame, originalFrame) || !bytes.Equal(plain, original) {
				t.Fatalf("dialect %#x decryption aliased an input at size %d", dialect, size)
			}
		}
	}
}

func BenchmarkSMBTransform(b *testing.B) {
	key := make([]byte, 16)
	for _, mode := range []struct {
		name    string
		dialect uint16
	}{{"CCM", 0x0300}, {"GCM", 0x0311}} {
		b.Run(mode.name, func(b *testing.B) {
			for _, size := range []struct {
				name string
				n    int
			}{{"64B", 64}, {"4KiB", 4096}, {"64KiB", 65536}} {
				b.Run(size.name, func(b *testing.B) {
					plain := make([]byte, size.n)
					frame, err := encryptSMB(mode.dialect, key, 123, plain)
					if err != nil {
						b.Fatal(err)
					}
					b.Run("encrypt", func(b *testing.B) {
						b.ReportAllocs()
						b.SetBytes(int64(size.n))
						for i := 0; i < b.N; i++ {
							if _, err := encryptSMB(mode.dialect, key, 123, plain); err != nil {
								b.Fatal(err)
							}
						}
					})
					b.Run("decrypt", func(b *testing.B) {
						b.ReportAllocs()
						b.SetBytes(int64(size.n))
						for i := 0; i < b.N; i++ {
							if _, err := decryptSMB(mode.dialect, key, 123, frame); err != nil {
								b.Fatal(err)
							}
						}
					})
				})
			}
		})
	}
}

func TestKeyDerivationBoundaries(t *testing.T) {
	key, preauth := make([]byte, 16), make([]byte, 64)
	for _, dialect := range []uint16{0x0202, 0x0210, 0x0300, 0x0302, 0x0311} {
		sign, encrypt, decrypt, err := deriveKeys(dialect, key, preauth)
		if err != nil || len(sign) != 16 {
			t.Fatalf("derive %#x: %v", dialect, err)
		}
		if dialect < 0x0300 {
			if !bytes.Equal(sign, key) || encrypt != nil || decrypt != nil {
				t.Fatal("unexpected SMB2 keys")
			}
		} else if len(encrypt) != 16 || len(decrypt) != 16 || bytes.Equal(encrypt, decrypt) || bytes.Equal(sign, encrypt) {
			t.Fatal("SMB3 key purposes are not separated")
		}
	}
	if _, _, _, err := deriveKeys(0x0311, key, nil); err == nil {
		t.Fatal("accepted missing preauthentication hash")
	}
	if _, _, _, err := deriveKeys(0xffff, key, preauth); err == nil {
		t.Fatal("accepted unknown dialect")
	}
	if _, _, _, err := deriveKeys(0x0210, nil, nil); err == nil {
		t.Fatal("accepted absent session key")
	}
	if _, err := encryptSMB(0x0210, key, 1, make([]byte, 64)); err == nil {
		t.Fatal("SMB2 silently used SMB3 encryption")
	}
}

func FuzzDecryptSMB(f *testing.F) {
	f.Add([]byte("\xfdSMB"))
	f.Add(make([]byte, 116))
	f.Fuzz(func(t *testing.T, frame []byte) {
		for _, dialect := range []uint16{0x0300, 0x0311} {
			_, _ = decryptSMB(dialect, make([]byte, 16), 1, frame)
		}
	})
}
