//go:build unit

package requestjwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/require"
)

// TestIssuer is an OIDC issuer for tests
// It serves an OIDC discovery document and a JWKS over TLS, and signs tokens with ES256
type TestIssuer struct {
	// URL of the issuer, which is also the value of the `iss` claim
	URL string

	t   *testing.T
	srv *httptest.Server

	lock sync.Mutex
	// Private keys whose public halves are published in the JWKS
	keys []jwk.Key
	// Additional keys published in the JWKS as-is
	extraJWKS []jwk.Key
	// When set, the discovery document claims this issuer instead of URL
	discoveryIssuer string
	// Paths the issuer answers with a redirect, and their targets
	redirects map[string]string
}

// NewTestIssuer starts an issuer with one signing key, which is stopped when the test ends
func NewTestIssuer(t *testing.T) *TestIssuer {
	t.Helper()

	i := &TestIssuer{t: t}
	i.srv = httptest.NewTLSServer(http.HandlerFunc(i.handle))
	i.URL = i.srv.URL
	t.Cleanup(i.srv.Close)

	i.AddKey("key-1")

	return i
}

// HTTPClient returns an HTTP client created by NewHTTPClient, which trusts the issuer's TLS certificate
// The issuer listens on a loopback address, so the client allows connections to private addresses
func (i *TestIssuer) HTTPClient() *http.Client {
	return NewHTTPClient(HTTPClientOptions{
		AllowPrivateAddresses: true,
		TLSConfig:             i.TLSConfig(),
	})
}

// TLSConfig returns a TLS configuration that trusts the issuer's certificate
func (i *TestIssuer) TLSConfig() *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(i.srv.Certificate())

	return &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}
}

// Redirect makes the issuer answer requests for path with a redirect to target
func (i *TestIssuer) Redirect(path string, target string) {
	i.lock.Lock()
	defer i.lock.Unlock()

	if i.redirects == nil {
		i.redirects = map[string]string{}
	}
	i.redirects[path] = target
}

// JWKSURL returns the URL of the issuer's JWKS
func (i *TestIssuer) JWKSURL() string {
	return i.URL + "/jwks"
}

// AddKey generates a new signing key, publishes it in the JWKS, and makes it the key new tokens are signed with
func (i *TestIssuer) AddKey(kid string) jwk.Key {
	i.t.Helper()

	key := NewTestSigningKey(i.t, kid)

	i.lock.Lock()
	i.keys = append(i.keys, key)
	i.lock.Unlock()

	return key
}

// CurrentKey returns the private key new tokens are signed with
func (i *TestIssuer) CurrentKey() jwk.Key {
	i.lock.Lock()
	defer i.lock.Unlock()

	return i.keys[len(i.keys)-1]
}

// RotateKey replaces every published key with a new one
func (i *TestIssuer) RotateKey(kid string) jwk.Key {
	i.t.Helper()

	i.lock.Lock()
	i.keys = nil
	i.lock.Unlock()

	return i.AddKey(kid)
}

// PublishExtraKey adds a key to the JWKS as-is, without using it to sign tokens
func (i *TestIssuer) PublishExtraKey(key jwk.Key) {
	i.lock.Lock()
	i.extraJWKS = append(i.extraJWKS, key)
	i.lock.Unlock()
}

// SetDiscoveryIssuer makes the discovery document claim a different issuer
func (i *TestIssuer) SetDiscoveryIssuer(issuer string) {
	i.lock.Lock()
	i.discoveryIssuer = issuer
	i.lock.Unlock()
}

// Token returns a token signed with the issuer's current key, for the given subject and audience, valid for 5 minutes
// The mutate functions can change the claims before the token is signed
func (i *TestIssuer) Token(subject string, audience string, mutate ...func(b *jwt.Builder)) string {
	i.t.Helper()

	key := i.CurrentKey()

	now := time.Now()
	b := jwt.NewBuilder().
		Issuer(i.URL).
		Subject(subject).
		Audience([]string{audience}).
		IssuedAt(now).
		Expiration(now.Add(5 * time.Minute))
	for _, fn := range mutate {
		fn(b)
	}

	return SignTestToken(i.t, key, b)
}

// NewTestSigningKey generates an ES256 private key with the given key ID
func NewTestSigningKey(t *testing.T, kid string) jwk.Key {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	key, err := jwk.Import[jwk.Key](priv)
	require.NoError(t, err)
	err = key.Set(jwk.KeyIDKey, kid)
	require.NoError(t, err)
	err = key.Set(jwk.AlgorithmKey, jwa.ES256())
	require.NoError(t, err)

	return key
}

// SignTestToken builds the token and signs it with key, using ES256
func SignTestToken(t *testing.T, key jwk.Key, b *jwt.Builder) string {
	t.Helper()

	tok, err := b.Build()
	require.NoError(t, err)

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), key))
	require.NoError(t, err)

	return string(signed)
}

func (i *TestIssuer) handle(w http.ResponseWriter, r *http.Request) {
	i.lock.Lock()
	target, redirect := i.redirects[r.URL.Path]
	i.lock.Unlock()
	if redirect {
		http.Redirect(w, r, target, http.StatusFound)
		return
	}

	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		i.lock.Lock()
		issuer := i.URL
		if i.discoveryIssuer != "" {
			issuer = i.discoveryIssuer
		}
		i.lock.Unlock()

		writeTestJSON(w, map[string]any{
			"issuer":   issuer,
			"jwks_uri": i.JWKSURL(),
		})

	case "/jwks":
		i.lock.Lock()
		set := jwk.NewSet()
		for _, key := range i.keys {
			pub, err := jwk.PublicKeyOf(key)
			if err != nil {
				i.lock.Unlock()
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = set.AddKey(pub)
		}
		for _, key := range i.extraJWKS {
			_ = set.AddKey(key)
		}
		i.lock.Unlock()

		writeTestJSON(w, set)

	default:
		http.NotFound(w, r)
	}
}

func writeTestJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
