package requestjwt

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/require"
)

const (
	mockIssuer       = "https://issuer.example.com"
	mockDiscoveryURL = mockIssuer + "/.well-known/openid-configuration"
	// The JWKS is on a different host than the issuer
	mockJWKSURL = "https://keys.example.com/jwks"
)

// mockTransport is an http.RoundTripper that serves responses from in-memory handlers, and records the requests it receives
// Requests for URLs without a handler fail, as if the host were unreachable
type mockTransport struct {
	lock     sync.Mutex
	handlers map[string]http.HandlerFunc
	requests []mockRequest
}

type mockRequest struct {
	URL    string
	Header http.Header
}

func newMockTransport() *mockTransport {
	return &mockTransport{
		handlers: map[string]http.HandlerFunc{},
	}
}

// Handle sets the handler for requests to u, replacing the existing one
func (m *mockTransport) Handle(u string, h http.HandlerFunc) {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.handlers[u] = h
}

// Requests returns the requests made to u
func (m *mockTransport) Requests(u string) []mockRequest {
	m.lock.Lock()
	defer m.lock.Unlock()

	var res []mockRequest
	for _, r := range m.requests {
		if r.URL == u {
			res = append(res, r)
		}
	}

	return res
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	u := req.URL.String()

	m.lock.Lock()
	m.requests = append(m.requests, mockRequest{
		URL:    u,
		Header: req.Header.Clone(),
	})
	h, ok := m.handlers[u]
	m.lock.Unlock()

	if !ok {
		return nil, fmt.Errorf("mock transport: no route to %s", u)
	}

	rec := httptest.NewRecorder()
	h(rec, req)

	res := rec.Result()
	res.Request = req
	return res, nil
}

// newMockVerifier returns a Verifier whose requests are served by m
// It uses the HTTP client from NewHTTPClient, so the redirect policy applies, with m as its transport
func newMockVerifier(t *testing.T, m *mockTransport) *Verifier {
	t.Helper()

	client := NewHTTPClient(HTTPClientOptions{})
	client.Transport = m

	v := NewVerifier(NewVerifierOptions{
		HTTPClient: client,
		Logger:     slog.New(slog.DiscardHandler),
	})
	t.Cleanup(func() {
		_ = v.Close(t.Context())
	})

	return v
}

func respondJSON(status int, body any) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}
}

func respondRaw(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

// mockDiscoveryDocument returns a discovery document for the issuer, with the given JWKS URL
func mockDiscoveryDocument(issuer string, jwksURL string) map[string]any {
	return map[string]any{
		"issuer":   issuer,
		"jwks_uri": jwksURL,
	}
}

// publicJWKS returns a JWKS with the public keys of the given private keys
func publicJWKS(t *testing.T, keys ...jwk.Key) jwk.Set {
	t.Helper()

	set := jwk.NewSet()
	for _, key := range keys {
		pub, err := jwk.PublicKeyOf(key)
		require.NoError(t, err)
		err = set.AddKey(pub)
		require.NoError(t, err)
	}

	return set
}

// mockToken returns a token for testSubject and testAudience, issued by issuer and signed with key
func mockToken(t *testing.T, key jwk.Key, issuer string) string {
	t.Helper()

	return SignTestToken(t, key, jwt.NewBuilder().
		Issuer(issuer).
		Subject(testSubject).
		Audience([]string{testAudience}).
		Expiration(time.Now().Add(5*time.Minute)))
}

func TestVerifierMockedDiscovery(t *testing.T) {
	key := NewTestSigningKey(t, "key-1")
	token := mockToken(t, key, mockIssuer)
	cfg := IssuerConfig{
		Issuer:   mockIssuer,
		Audience: testAudience,
		Subject:  testSubject,
	}

	t.Run("resolves the JWKS URL and caches the discovery document", func(t *testing.T) {
		m := newMockTransport()
		m.Handle(mockDiscoveryURL, respondJSON(http.StatusOK, mockDiscoveryDocument(mockIssuer, mockJWKSURL)))
		m.Handle(mockJWKSURL, respondJSON(http.StatusOK, publicJWKS(t, key)))

		v := newMockVerifier(t, m)
		now := time.Now()
		v.now = func() time.Time {
			return now
		}

		claims, err := v.Verify(t.Context(), token, cfg)
		require.NoError(t, err)
		require.Equal(t, testSubject, claims.Subject)

		discoveryRequests := m.Requests(mockDiscoveryURL)
		require.Len(t, discoveryRequests, 1)
		require.Equal(t, "application/json", discoveryRequests[0].Header.Get("Accept"))
		require.NotEmpty(t, m.Requests(mockJWKSURL))

		// The discovery document is cached until its TTL expires
		now = now.Add(discoverySuccessTTL - time.Second)
		_, err = v.Verify(t.Context(), token, cfg)
		require.NoError(t, err)
		require.Len(t, m.Requests(mockDiscoveryURL), 1)

		now = now.Add(2 * time.Second)
		_, err = v.Verify(t.Context(), token, cfg)
		require.NoError(t, err)
		require.Len(t, m.Requests(mockDiscoveryURL), 2)
	})

	t.Run("caches failures for a short time", func(t *testing.T) {
		m := newMockTransport()
		m.Handle(mockDiscoveryURL, respondRaw(http.StatusInternalServerError, "unavailable"))
		m.Handle(mockJWKSURL, respondJSON(http.StatusOK, publicJWKS(t, key)))

		v := newMockVerifier(t, m)
		now := time.Now()
		v.now = func() time.Time {
			return now
		}

		_, err := v.Verify(t.Context(), token, cfg)
		require.ErrorIs(t, err, ErrKeyFetch)
		require.ErrorContains(t, err, "unexpected status code 500")
		require.Len(t, m.Requests(mockDiscoveryURL), 1)

		// The issuer recovers, but the failure is still cached
		m.Handle(mockDiscoveryURL, respondJSON(http.StatusOK, mockDiscoveryDocument(mockIssuer, mockJWKSURL)))
		now = now.Add(discoveryFailureTTL - time.Second)
		_, err = v.Verify(t.Context(), token, cfg)
		require.ErrorIs(t, err, ErrKeyFetch)
		require.Len(t, m.Requests(mockDiscoveryURL), 1)

		// Once the failure expires, the document is fetched again
		now = now.Add(2 * time.Second)
		_, err = v.Verify(t.Context(), token, cfg)
		require.NoError(t, err)
		require.Len(t, m.Requests(mockDiscoveryURL), 2)
	})

	t.Run("configured JWKS URL skips discovery", func(t *testing.T) {
		const jwksURL = "https://other-keys.example.com/keys.json"

		m := newMockTransport()
		m.Handle(jwksURL, respondJSON(http.StatusOK, publicJWKS(t, key)))

		v := newMockVerifier(t, m)
		withJWKSURL := cfg
		withJWKSURL.JWKSURL = jwksURL
		_, err := v.Verify(t.Context(), token, withJWKSURL)
		require.NoError(t, err)
		require.Empty(t, m.Requests(mockDiscoveryURL))
		require.NotEmpty(t, m.Requests(jwksURL))
	})

	t.Run("issuer with a path", func(t *testing.T) {
		// A trailing slash is part of the issuer, but it isn't repeated in the discovery URL
		const issuer = "https://login.example.com/tenant-1/"
		const discoveryURL = "https://login.example.com/tenant-1/.well-known/openid-configuration"

		m := newMockTransport()
		m.Handle(discoveryURL, respondJSON(http.StatusOK, mockDiscoveryDocument(issuer, mockJWKSURL)))
		m.Handle(mockJWKSURL, respondJSON(http.StatusOK, publicJWKS(t, key)))

		v := newMockVerifier(t, m)
		pathCfg := cfg
		pathCfg.Issuer = issuer
		_, err := v.Verify(t.Context(), mockToken(t, key, issuer), pathCfg)
		require.NoError(t, err)
		require.Len(t, m.Requests(discoveryURL), 1)
	})
}

func TestVerifierMockedDiscoveryRejected(t *testing.T) {
	key := NewTestSigningKey(t, "key-1")
	token := mockToken(t, key, mockIssuer)

	tests := []struct {
		name      string
		discovery http.HandlerFunc
		errMsg    string
	}{
		{
			name:   "unreachable",
			errMsg: "no route to",
		},
		{
			name:      "not found",
			discovery: respondRaw(http.StatusNotFound, "not found"),
			errMsg:    "unexpected status code 404",
		},
		{
			name: "redirect",
			discovery: func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "https://elsewhere.example.com/.well-known/openid-configuration", http.StatusFound)
			},
			errMsg: "redirects are not allowed",
		},
		{
			name:      "invalid JSON",
			discovery: respondRaw(http.StatusOK, "{not json"),
			errMsg:    "failed to parse discovery document",
		},
		{
			name:      "too large",
			discovery: respondRaw(http.StatusOK, `{"issuer":"`+strings.Repeat("a", maxDiscoveryDocumentSize)+`"}`),
			errMsg:    "is larger than",
		},
		{
			name:      "different issuer",
			discovery: respondJSON(http.StatusOK, mockDiscoveryDocument(mockIssuer+"/", mockJWKSURL)),
			errMsg:    "is for issuer",
		},
		{
			name:      "missing jwks_uri",
			discovery: respondJSON(http.StatusOK, map[string]any{"issuer": mockIssuer}),
			errMsg:    "invalid jwks_uri",
		},
		{
			name:      "plain HTTP jwks_uri",
			discovery: respondJSON(http.StatusOK, mockDiscoveryDocument(mockIssuer, "http://keys.example.com/jwks")),
			errMsg:    "invalid jwks_uri",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newMockTransport()
			if tt.discovery != nil {
				m.Handle(mockDiscoveryURL, tt.discovery)
			}
			m.Handle(mockJWKSURL, respondJSON(http.StatusOK, publicJWKS(t, key)))

			v := newMockVerifier(t, m)
			_, err := v.Verify(t.Context(), token, IssuerConfig{
				Issuer:   mockIssuer,
				Audience: testAudience,
				Subject:  testSubject,
			})
			require.ErrorIs(t, err, ErrKeyFetch)
			require.ErrorContains(t, err, tt.errMsg)

			// Nothing is fetched from a document that was rejected
			require.Empty(t, m.Requests(mockJWKSURL))
		})
	}
}

func TestVerifierMockedJWKSRejected(t *testing.T) {
	key := NewTestSigningKey(t, "key-1")
	token := mockToken(t, key, mockIssuer)

	tests := []struct {
		name   string
		jwks   http.HandlerFunc
		errMsg string
	}{
		{
			name: "unreachable",
		},
		{
			name: "server error",
			jwks: respondRaw(http.StatusInternalServerError, "unavailable"),
		},
		{
			name: "redirect",
			jwks: func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "https://elsewhere.example.com/jwks", http.StatusFound)
			},
			errMsg: "redirects are not allowed",
		},
		{
			name: "invalid JSON",
			jwks: respondRaw(http.StatusOK, "{not json"),
		},
		{
			name:   "no keys",
			jwks:   respondJSON(http.StatusOK, map[string]any{"keys": []any{}}),
			errMsg: "doesn't contain any asymmetric keys",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newMockTransport()
			if tt.jwks != nil {
				m.Handle(mockJWKSURL, tt.jwks)
			}

			v := newMockVerifier(t, m)
			_, err := v.Verify(t.Context(), token, IssuerConfig{
				Issuer:   mockIssuer,
				Audience: testAudience,
				Subject:  testSubject,
				JWKSURL:  mockJWKSURL,
			})
			require.ErrorIs(t, err, ErrKeyFetch)
			if tt.errMsg != "" {
				require.ErrorContains(t, err, tt.errMsg)
			}
		})
	}
}
