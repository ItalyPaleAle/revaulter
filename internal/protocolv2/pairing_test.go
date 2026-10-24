package protocolv2

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func randomB64(t *testing.T, size int) string {
	t.Helper()

	b := make([]byte, size)
	_, err := rand.Read(b)
	require.NoError(t, err)

	return b64(b)
}

func testPairingPayload(t *testing.T) PairingPayload {
	t.Helper()

	fp := sha256.Sum256([]byte("anchor"))
	return PairingPayload{
		Server:            "https://vault.example.com",
		UserID:            "user-123",
		SessionID:         randomB64(t, PairingSessionIDSize),
		Secret:            randomB64(t, PairingSecretSize),
		AnchorFingerprint: hex.EncodeToString(fp[:]),
		V:                 PairingVersion,
	}
}

// testPairingHello builds a hello the way the new device does: sign the transcript with both keys, then MAC it
func testPairingHello(t *testing.T, payload PairingPayload, d *testDevice) (*PairingHello, PairingTranscript) {
	t.Helper()

	hello := &PairingHello{
		DeviceName:   "iPhone 17 Pro",
		CredentialID: randomB64(t, DeviceCredentialIDSize),
		PublicKeys:   d.public,
	}
	transcript := NewPairingTranscript(payload.Server, payload.UserID, payload.SessionID, payload.AnchorFingerprint, hello)

	sigP256, sigMldsa65 := d.sign(t, CanonicalPairingHelloMessage(&transcript))
	hello.SignatureP256 = b64(sigP256)
	hello.SignatureMldsa65 = b64(sigMldsa65)

	macKey, err := payload.MACKey()
	require.NoError(t, err)
	hello.MAC = b64(PairingHelloMAC(macKey, &transcript))

	return hello, transcript
}

func TestPairingPayloadRoundTrip(t *testing.T) {
	payload := testPairingPayload(t)

	t.Run("text form", func(t *testing.T) {
		require.True(t, strings.HasPrefix(payload.String(), PairingPayloadPrefix))
		parsed, err := ParsePairingPayload(payload.String())
		require.NoError(t, err)
		require.Equal(t, payload, parsed)
	})

	t.Run("link form", func(t *testing.T) {
		require.True(t, strings.HasPrefix(payload.Link(), PairingLinkPrefix))
		parsed, err := ParsePairingPayload(payload.Link())
		require.NoError(t, err)
		require.Equal(t, payload, parsed)
	})

	t.Run("pasted with surrounding whitespace", func(t *testing.T) {
		parsed, err := ParsePairingPayload("  " + payload.String() + "\n")
		require.NoError(t, err)
		require.Equal(t, payload, parsed)
	})
}

func TestParsePairingPayloadRejectsMalformedInput(t *testing.T) {
	payload := testPairingPayload(t)

	tests := []struct {
		name   string
		input  string
		errMsg string
	}{
		{"empty", "", "not a Revaulter pairing payload"},
		{"no prefix", b64([]byte(payload.CanonicalBody())), "not a Revaulter pairing payload"},
		{"web URL", "https://vault.example.com/pair", "not a Revaulter pairing payload"},
		{"not base64url", PairingPayloadPrefix + "not base64!", "not valid base64url"},
		{"missing a line", PairingPayloadPrefix + b64([]byte(strings.TrimSuffix(payload.CanonicalBody(), "\nv=1"))), "invalid pairing payload"},
		{"wrong key order", PairingPayloadPrefix + b64([]byte("userId=a\nserver=b\nsessionId=c\nsecret=d\nanchorFingerprint=e\nv=1")), "invalid pairing payload"},
		{"too long", PairingPayloadPrefix + strings.Repeat("A", maxPairingPayloadLength), "at most"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParsePairingPayload(tc.input)
			require.Error(t, err)
			require.ErrorContains(t, err, tc.errMsg)
		})
	}
}

func TestPairingPayloadValidate(t *testing.T) {
	t.Run("accepted servers", func(t *testing.T) {
		for _, server := range []string{
			"https://vault.example.com",
			"https://vault.example.com/",
			"https://example.com:8443/revaulter",
			"http://localhost:8080",
			"http://127.0.0.1:8080",
			"http://[::1]:8080",
		} {
			p := testPairingPayload(t)
			p.Server = server
			err := p.Validate()
			require.NoError(t, err, server)
		}
	})

	tests := []struct {
		name   string
		mutate func(p *PairingPayload)
		errMsg string
	}{
		{"unknown version", func(p *PairingPayload) { p.V = 2 }, "unsupported pairing version"},
		{"http on a public host", func(p *PairingPayload) { p.Server = "http://vault.example.com" }, "must use https"},
		{"http on a private address", func(p *PairingPayload) { p.Server = "http://192.168.1.10" }, "must use https"},
		{"other scheme", func(p *PairingPayload) { p.Server = "ftp://vault.example.com" }, "unsupported server scheme"},
		{"relative URL", func(p *PairingPayload) { p.Server = "/vault" }, "absolute URL"},
		{"credentials in URL", func(p *PairingPayload) { p.Server = "https://user:pass@vault.example.com" }, "credentials"},
		{"query in URL", func(p *PairingPayload) { p.Server = "https://vault.example.com/?a=b" }, "query or fragment"},
		{"fragment in URL", func(p *PairingPayload) { p.Server = "https://vault.example.com/#a" }, "query or fragment"},
		{"empty user ID", func(p *PairingPayload) { p.UserID = "" }, "userId is empty"},
		{"newline in user ID", func(p *PairingPayload) { p.UserID = "a\nv=2" }, "control character"},
		{"short session ID", func(p *PairingPayload) { p.SessionID = randomB64(t, 8) }, "sessionId must be 16 bytes"},
		{"short secret", func(p *PairingPayload) { p.Secret = randomB64(t, 16) }, "secret must be 32 bytes"},
		{"uppercase fingerprint", func(p *PairingPayload) { p.AnchorFingerprint = strings.ToUpper(p.AnchorFingerprint) }, "lowercase hex"},
		{"short fingerprint", func(p *PairingPayload) { p.AnchorFingerprint = p.AnchorFingerprint[:62] }, "lowercase hex"},
		{"non-hex fingerprint", func(p *PairingPayload) { p.AnchorFingerprint = strings.Repeat("z", 64) }, "lowercase hex"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := testPairingPayload(t)
			tc.mutate(&p)
			err := p.Validate()
			require.Error(t, err)
			require.ErrorContains(t, err, tc.errMsg)
		})
	}
}

func TestPairingMACKey(t *testing.T) {
	payload := testPairingPayload(t)

	key1, err := payload.MACKey()
	require.NoError(t, err)
	require.Len(t, key1, sha256.Size)

	key2, err := payload.MACKey()
	require.NoError(t, err)
	require.Equal(t, key1, key2)

	// The key is bound to the session ID
	other := payload
	other.SessionID = randomB64(t, PairingSessionIDSize)
	key3, err := other.MACKey()
	require.NoError(t, err)
	require.NotEqual(t, key1, key3)

	_, err = PairingMACKey(make([]byte, 16), payload.SessionID)
	require.Error(t, err)
}

func TestPairingHello(t *testing.T) {
	payload := testPairingPayload(t)
	d := newTestDevice(t)
	hello, transcript := testPairingHello(t, payload, d)
	macKey, err := payload.MACKey()
	require.NoError(t, err)

	sigP256 := mustDecodeB64(t, hello.SignatureP256)
	sigMldsa65 := mustDecodeB64(t, hello.SignatureMldsa65)
	mac := mustDecodeB64(t, hello.MAC)

	t.Run("valid hello", func(t *testing.T) {
		keys, err := hello.Validate()
		require.NoError(t, err)

		err = VerifyPairingHelloSignatures(keys, &transcript, sigP256, sigMldsa65)
		require.NoError(t, err)

		err = VerifyPairingHelloMAC(macKey, &transcript, mac)
		require.NoError(t, err)
	})

	// Each change to the transcript must break the MAC, and the signatures too
	mutations := map[string]func(tr *PairingTranscript){
		"server":            func(tr *PairingTranscript) { tr.Server = "https://evil.example.com" },
		"user ID":           func(tr *PairingTranscript) { tr.UserID = "user-456" },
		"anchor":            func(tr *PairingTranscript) { tr.AnchorFingerprint = strings.Repeat("0", 64) },
		"credential ID":     func(tr *PairingTranscript) { tr.CredentialID = randomB64(t, DeviceCredentialIDSize) },
		"device name":       func(tr *PairingTranscript) { tr.DeviceName = "MacBook Pro" },
		"key agreement key": func(tr *PairingTranscript) { tr.KaP256 = newTestDevice(t).public.KaP256 },
		"ML-KEM key":        func(tr *PairingTranscript) { tr.KemMlkem768 = newTestDevice(t).public.KemMlkem768 },
	}
	for name, mutate := range mutations {
		t.Run("tampered "+name, func(t *testing.T) {
			tampered := transcript
			mutate(&tampered)

			err := VerifyPairingHelloMAC(macKey, &tampered, mac)
			require.Error(t, err)

			err = VerifyPairingHelloSignatures(d.parsed(t), &tampered, sigP256, sigMldsa65)
			require.Error(t, err)
		})
	}

	t.Run("MAC under another secret", func(t *testing.T) {
		other := payload
		other.Secret = randomB64(t, PairingSecretSize)
		otherKey, err := other.MACKey()
		require.NoError(t, err)

		err = VerifyPairingHelloMAC(otherKey, &transcript, mac)
		require.Error(t, err)
		require.ErrorContains(t, err, "verification failed")
	})

	t.Run("truncated MAC", func(t *testing.T) {
		err := VerifyPairingHelloMAC(macKey, &transcript, mac[:16])
		require.Error(t, err)
	})

	t.Run("unknown transcript version", func(t *testing.T) {
		other := transcript
		other.V = 2

		err := VerifyPairingHelloMAC(macKey, &other, mac)
		require.Error(t, err)

		err = VerifyPairingHelloSignatures(d.parsed(t), &other, sigP256, sigMldsa65)
		require.Error(t, err)
	})
}

func TestPairingHelloValidate(t *testing.T) {
	payload := testPairingPayload(t)
	hello, _ := testPairingHello(t, payload, newTestDevice(t))

	tests := []struct {
		name   string
		mutate func(h *PairingHello)
		errMsg string
	}{
		{"empty device name", func(h *PairingHello) { h.DeviceName = "" }, "deviceName is empty"},
		{"long device name", func(h *PairingHello) { h.DeviceName = strings.Repeat("a", MaxDeviceNameLength+1) }, "at most 100 bytes"},
		{"newline in device name", func(h *PairingHello) { h.DeviceName = "iPhone\nv=2" }, "control character"},
		{"invalid UTF-8 device name", func(h *PairingHello) { h.DeviceName = "\xff" }, "not valid UTF-8"},
		{"short credential ID", func(h *PairingHello) { h.CredentialID = randomB64(t, 8) }, "credentialId must be 16 bytes"},
		{"invalid public keys", func(h *PairingHello) { h.PublicKeys.KaP256 = h.PublicKeys.SignP256 }, "must be different keys"},
		{"DER P-256 signature size", func(h *PairingHello) { h.SignatureP256 = randomB64(t, 72) }, "signatureP256 must be 64 bytes"},
		{"ML-DSA-87 signature size", func(h *PairingHello) { h.SignatureMldsa65 = randomB64(t, MLDSA87SignatureSize) }, "signatureMldsa65 must be 3309 bytes"},
		{"short MAC", func(h *PairingHello) { h.MAC = randomB64(t, 16) }, "mac must be 32 bytes"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := *hello
			tc.mutate(&h)
			_, err := h.Validate()
			require.Error(t, err)
			require.ErrorContains(t, err, tc.errMsg)
		})
	}
}

func TestPairingNonceAndCode(t *testing.T) {
	payload := testPairingPayload(t)
	hello, _ := testPairingHello(t, payload, newTestDevice(t))
	macKey, err := payload.MACKey()
	require.NoError(t, err)

	nonce := &PairingNoncePayload{
		HelloMAC: hello.MAC,
		Nonce:    randomB64(t, PairingNonceSize),
		V:        PairingVersion,
	}
	mac := PairingNonceMAC(macKey, nonce)

	t.Run("valid nonce MAC", func(t *testing.T) {
		err := VerifyPairingNonceMAC(macKey, nonce, mac)
		require.NoError(t, err)
	})

	t.Run("tampered nonce", func(t *testing.T) {
		other := *nonce
		other.Nonce = randomB64(t, PairingNonceSize)
		err := VerifyPairingNonceMAC(macKey, &other, mac)
		require.Error(t, err)
	})

	t.Run("nonce for another hello", func(t *testing.T) {
		other := *nonce
		other.HelloMAC = randomB64(t, PairingMACSize)
		err := VerifyPairingNonceMAC(macKey, &other, mac)
		require.Error(t, err)
	})

	t.Run("wrong sizes", func(t *testing.T) {
		other := *nonce
		other.Nonce = randomB64(t, 16)
		err := VerifyPairingNonceMAC(macKey, &other, mac)
		require.Error(t, err)
		require.ErrorContains(t, err, "nonce must be 32 bytes")
	})

	t.Run("code", func(t *testing.T) {
		code := PairingCode(macKey, nonce)
		require.Regexp(t, `^[0-9]{6}$`, code)

		// Both sides compute the same code from the same inputs
		require.Equal(t, code, PairingCode(macKey, nonce))

		// A different nonce or hello gives a different code, except for a one-in-a-million collision
		otherNonce := *nonce
		otherNonce.Nonce = b64(make([]byte, PairingNonceSize))
		otherHello := *nonce
		otherHello.HelloMAC = b64(make([]byte, PairingMACSize))
		differs := PairingCode(macKey, &otherNonce) != code || PairingCode(macKey, &otherHello) != code
		require.True(t, differs)
	})
}

func FuzzParsePairingPayload(f *testing.F) {
	f.Add(PairingPayload{
		Server:            "https://vault.example.com",
		UserID:            "user-123",
		SessionID:         b64(make([]byte, PairingSessionIDSize)),
		Secret:            b64(make([]byte, PairingSecretSize)),
		AnchorFingerprint: strings.Repeat("ab", 32),
		V:                 PairingVersion,
	}.String())
	f.Add(PairingPayloadPrefix)
	f.Add("")

	f.Fuzz(func(t *testing.T, input string) {
		p, err := ParsePairingPayload(input)
		if err != nil {
			return
		}

		// Anything that parses must survive a round trip through both forms
		fromText, err := ParsePairingPayload(p.String())
		require.NoError(t, err)
		require.Equal(t, p, fromText)

		fromLink, err := ParsePairingPayload(p.Link())
		require.NoError(t, err)
		require.Equal(t, p, fromLink)
	})
}

func mustDecodeB64(t *testing.T, s string) []byte {
	t.Helper()

	b, err := decodeBase64Field("value", s, 0)
	require.NoError(t, err)

	return b
}
