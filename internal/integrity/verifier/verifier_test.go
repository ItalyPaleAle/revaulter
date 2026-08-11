package verifier

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

// newStubServer returns an httptest.Server whose handlers are looked up by path
// Test cases hand in a path→handler map; missing paths 404
func newStubServer(t *testing.T, handlers map[string]http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	for p, h := range handlers {
		mux.HandleFunc(p, h)
	}
	return httptest.NewServer(mux)
}

func newStubTLSServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(handler)
	srv.EnableHTTP2 = true
	err := http2.ConfigureServer(srv.Config, &http2.Server{})
	require.NoError(t, err)
	srv.StartTLS()
	return srv
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func TestCheck_EmptyServerRejected(t *testing.T) {
	_, err := Check(t.Context(), Options{})
	require.Error(t, err)
	require.ErrorContains(t, err, "server is required")
}

func TestCheck_ServerUnreachable(t *testing.T) {
	// A closed httptest server: connect attempts fail immediately
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	srv.Close()

	_, err := Check(t.Context(), Options{Server: srv.URL})
	require.Error(t, err)
	require.ErrorContains(t, err, "fetch /info")
}

func TestCheck_HasIntegrityFalseReturnsSentinel(t *testing.T) {
	srv := newStubServer(t, map[string]http.HandlerFunc{
		"/info": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, InfoResponse{
				Product:      "revaulter",
				APIVersion:   2,
				Version:      "v1.0.0",
				Commit:       "abc",
				BuildDate:    "2026-04-16T00:00:00Z",
				HasIntegrity: false,
			})
		},
	})
	defer srv.Close()

	_, err := Check(t.Context(), Options{Server: srv.URL})
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNoIntegrity)
}

func TestCheck_UnexpectedAPIVersion(t *testing.T) {
	srv := newStubServer(t, map[string]http.HandlerFunc{
		"/info": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, InfoResponse{APIVersion: 1, Version: "v1.0.0", HasIntegrity: true})
		},
	})
	defer srv.Close()

	_, err := Check(t.Context(), Options{Server: srv.URL})
	require.Error(t, err)
	require.ErrorIs(t, err, ErrUnexpectedAPIVer)
}

func TestCheck_IntegrityEndpoint404(t *testing.T) {
	srv := newStubServer(t, map[string]http.HandlerFunc{
		"/info": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, InfoResponse{APIVersion: 2, Version: "v1.0.0", HasIntegrity: true})
		},
	})
	defer srv.Close()

	_, err := Check(t.Context(), Options{Server: srv.URL})
	require.Error(t, err)
	require.ErrorContains(t, err, "fetch /info/integrity")
}

func TestCheck_EmptyManifestRejected(t *testing.T) {
	srv := newStubServer(t, map[string]http.HandlerFunc{
		"/info": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, InfoResponse{APIVersion: 2, Version: "v1.0.0", HasIntegrity: true})
		},
		"/info/integrity": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, map[string]any{"manifest": "", "bundle": json.RawMessage("{}")})
		},
	})
	defer srv.Close()

	_, err := Check(t.Context(), Options{Server: srv.URL})
	require.Error(t, err)
	require.ErrorContains(t, err, "empty manifest")
}

func TestCheck_BundleVerificationFailsWithNoFallback(t *testing.T) {
	// Any well-formed-but-not-a-Sigstore-bundle will fail the primary verify step
	// With NoRekorFallback, the error should surface directly (not attempt fallback)
	srv := newStubServer(t, map[string]http.HandlerFunc{
		"/info": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, InfoResponse{APIVersion: 2, Version: "v1.0.0", HasIntegrity: true})
		},
		"/info/integrity": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, map[string]any{
				"manifest": "v1.0.0|abc\n2026-04-16T00:00:00Z\n",
				"bundle":   json.RawMessage(`{"not":"a bundle"}`),
			})
		},
	})
	defer srv.Close()

	_, err := Check(t.Context(), Options{Server: srv.URL, NoRekorFallback: true})
	require.Error(t, err)
	require.ErrorContains(t, err, "signature verification failed")
}

func TestMismatch_StringSize(t *testing.T) {
	m := Mismatch{Path: "index.html", Reason: "size", Expected: "100", Actual: "101"}
	assert.Equal(t, "index.html: size mismatch (manifest=100, actual=101)", m.String())
}

func TestMismatch_StringSha256(t *testing.T) {
	m := Mismatch{Path: "app.js", Reason: "sha256", Expected: "aa", Actual: "bb"}
	assert.Equal(t, "app.js: sha256 mismatch (manifest=aa, actual=bb)", m.String())
}

func TestNewHTTPClient_InvalidURL(t *testing.T) {
	_, err := NewHTTPClient("://bad", false, false)
	require.Error(t, err)
}

func TestNewHTTPClient_HTTPAllowsH2C(t *testing.T) {
	c, err := NewHTTPClient("http://localhost:8080", false, false)
	require.NoError(t, err)
	require.NotNil(t, c)
}

func TestNewHTTPClient_InsecureSkipsTLSVerify(t *testing.T) {
	c, err := NewHTTPClient("https://localhost", true, false)
	require.NoError(t, err)
	require.NotNil(t, c)
}

func TestNewHTTPClient_DoesNotFollowRedirects(t *testing.T) {
	redirected := false
	target := newStubTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected = true
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	srv := newStubTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer srv.Close()

	client, err := NewHTTPClient(srv.URL, true, true)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	require.NoError(t, err)

	res, err := client.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()

	assert.Equal(t, http.StatusFound, res.StatusCode)
	assert.False(t, redirected)
	assert.Equal(t, target.URL, res.Header.Get("Location"))
}

// Small sanity test for doJSONRequest's error path (caller sees the server-side "error" field)
func TestDoJSONRequest_PropagatesServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "boom"})
	}))
	defer srv.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	require.NoError(t, err)
	var out map[string]any
	err = doJSONRequest(http.DefaultClient, req, &out)
	require.Error(t, err)
	require.ErrorContains(t, err, "boom")
	require.ErrorContains(t, err, "500")
}
