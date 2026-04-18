package integrity

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyBundle_RejectsEmptyInputs(t *testing.T) {
	_, err := VerifyBundle(nil, []byte("{}"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "manifest is empty")

	_, err = VerifyBundle([]byte("manifest"), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bundle is empty")
}

func TestVerifyBundle_RejectsMalformedBundle(t *testing.T) {
	// Valid JSON but not a Sigstore bundle
	_, err := VerifyBundle([]byte("some manifest"), []byte(`{"foo":"bar"}`))
	require.Error(t, err)
	// sigstore-go's UnmarshalJSON rejects anything that's not a Sigstore bundle
	assert.Contains(t, err.Error(), "parse signing bundle")

	// Not valid JSON at all
	_, err = VerifyBundle([]byte("some manifest"), []byte(`not json`))
	require.Error(t, err)
}

func TestLoadTrustedRoot_EmbeddedJSONParses(t *testing.T) {
	// The embedded sigstore trust root JSON must parse; this is a regression guard for
	// file-refresh workflows that might accidentally ship a truncated or broken copy
	tr, err := loadTrustedRoot()
	require.NoError(t, err)
	require.NotNil(t, tr)
}

func TestVerifyViaRekor_RejectsEmptyManifest(t *testing.T) {
	_, err := VerifyViaRekor(t.Context(), nil, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "manifest is empty")
}

func TestVerifyViaRekor_ReturnsErrorOnEmptyRekorResponse(t *testing.T) {
	// Stand up a fake Rekor that returns zero UUIDs for the hash search
	rekor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/index/retrieve":
			assert.Equal(t, http.MethodPost, r.Method)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer rekor.Close()

	_, err := VerifyViaRekor(t.Context(), []byte("some manifest"), rekor.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no rekor entries found")
}

func TestVerifyViaRekor_PropagatesHTTPError(t *testing.T) {
	rekor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer rekor.Close()

	_, err := VerifyViaRekor(t.Context(), []byte("x"), rekor.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rekor search by hash")
}

func TestRekorEntryAsBundle_RejectsWrongKind(t *testing.T) {
	// Build a body with kind != hashedrekord (e.g. intoto) and verify we reject it
	bodyWrap := map[string]any{
		"kind":       "intoto",
		"apiVersion": "0.0.1",
		"spec":       map[string]any{},
	}
	bodyJSON, err := json.Marshal(bodyWrap)
	require.NoError(t, err)

	entryResp := map[string]rekorLogEntry{
		"abc123": {
			Body:           base64.StdEncoding.EncodeToString(bodyJSON),
			IntegratedTime: 1700000000,
			LogID:          strings.Repeat("0", 64),
			LogIndex:       1,
			Verification: rekorVerification{
				SignedEntryTimestamp: base64.StdEncoding.EncodeToString([]byte("set")),
				InclusionProof: rekorInclusionProof{
					LogIndex:   1,
					RootHash:   strings.Repeat("a", 64),
					TreeSize:   2,
					Hashes:     []string{strings.Repeat("b", 64)},
					Checkpoint: "cp",
				},
			},
		},
	}

	rekor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/log/entries/") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(entryResp)
			return
		}
		http.NotFound(w, r)
	}))
	defer rekor.Close()

	digest := make([]byte, 32)
	_, err = rekorEntryAsBundle(context.Background(), rekor.URL, "abc123", digest)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported rekor entry kind")
}

func TestRekorInclusionProof_ToProto(t *testing.T) {
	p := rekorInclusionProof{
		LogIndex:   42,
		RootHash:   hex.EncodeToString([]byte("root-hash-bytes-here-0000-0000-00")),
		TreeSize:   100,
		Hashes:     []string{hex.EncodeToString([]byte("abcd"))},
		Checkpoint: "signed-checkpoint",
	}

	proto, err := p.toProto()
	require.NoError(t, err)
	assert.Equal(t, int64(42), proto.GetLogIndex())
	assert.Equal(t, int64(100), proto.GetTreeSize())
	assert.Equal(t, "signed-checkpoint", proto.GetCheckpoint().GetEnvelope())
	require.Len(t, proto.GetHashes(), 1)
	assert.Equal(t, []byte("abcd"), proto.GetHashes()[0])

	// Malformed hex is rejected
	bad := p
	bad.RootHash = "zz"
	_, err = bad.toProto()
	require.Error(t, err)
}

func TestParseHashedRekord_HappyPath(t *testing.T) {
	// Build a minimal hashedrekord body with a valid PEM cert and a signature
	// The cert doesn't need to chain to anything — this test covers the parser, not signature verification
	dummyCertPEM := `-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B
5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l
Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc
6MF9+Yw1Yy0t
-----END CERTIFICATE-----`
	pemB64 := base64.StdEncoding.EncodeToString([]byte(dummyCertPEM))
	sigB64 := base64.StdEncoding.EncodeToString([]byte("some-signature"))

	body := map[string]any{
		"kind":       "hashedrekord",
		"apiVersion": "0.0.1",
		"spec": map[string]any{
			"data": map[string]any{
				"hash": map[string]any{"algorithm": "sha256", "value": strings.Repeat("0", 64)},
			},
			"signature": map[string]any{
				"content":   sigB64,
				"publicKey": map[string]any{"content": pemB64},
			},
		},
	}
	bodyJSON, err := json.Marshal(body)
	require.NoError(t, err)

	sig, certDER, err := parseHashedRekord(bodyJSON)
	require.NoError(t, err)
	assert.Equal(t, []byte("some-signature"), sig)
	assert.NotEmpty(t, certDER)
}

func TestParseHashedRekord_RejectsNonPEMContent(t *testing.T) {
	body := map[string]any{
		"kind":       "hashedrekord",
		"apiVersion": "0.0.1",
		"spec": map[string]any{
			"signature": map[string]any{
				"content":   base64.StdEncoding.EncodeToString([]byte("x")),
				"publicKey": map[string]any{"content": base64.StdEncoding.EncodeToString([]byte("not a pem"))},
			},
		},
	}
	bodyJSON, err := json.Marshal(body)
	require.NoError(t, err)

	_, _, err = parseHashedRekord(bodyJSON)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PEM CERTIFICATE")
}
