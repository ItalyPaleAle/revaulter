package requestjwt

import (
	"context"
	"encoding/base64"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testAudience = "https://revaulter.example.com"
	testSubject  = "repo:example/app:ref:refs/tags/v1.2.3"
)

func TestMatchSubject(t *testing.T) {
	tests := []struct {
		pattern  string
		subject  string
		expected bool
	}{
		{pattern: "repo:a/b:ref:refs/heads/main", subject: "repo:a/b:ref:refs/heads/main", expected: true},
		{pattern: "repo:a/b:ref:refs/heads/main", subject: "repo:a/b:ref:refs/heads/mainx", expected: false},
		{pattern: "repo:a/b:ref:refs/heads/main", subject: "Repo:a/b:ref:refs/heads/main", expected: false},
		{pattern: "repo:a/b:ref:refs/tags/*", subject: "repo:a/b:ref:refs/tags/v1.0.0", expected: true},
		{pattern: "repo:a/b:ref:refs/tags/*", subject: "repo:a/b:ref:refs/tags/release/v1", expected: true},
		{pattern: "repo:a/b:ref:refs/tags/*", subject: "repo:a/b:ref:refs/tags/", expected: true},
		{pattern: "repo:a/b:ref:refs/tags/*", subject: "repo:a/bc:ref:refs/tags/v1", expected: false},
		{pattern: "repo:a/b:*", subject: "repo:a/b:environment:prod", expected: true},
		{pattern: "repo:*/b:*:prod", subject: "repo:a/b:environment:prod", expected: true},
		{pattern: "repo:*/b:*:prod", subject: "repo:a/b:environment:production", expected: false},
		{pattern: "*:prod", subject: "x:prod:prod", expected: true},
		{pattern: "a**b", subject: "ab", expected: true},
		{pattern: "a*b*c", subject: "aXbYbZc", expected: true},
		{pattern: "a*b*c", subject: "aXbYbZ", expected: false},
		{pattern: "abc", subject: "", expected: false},
		{pattern: "*", subject: "", expected: true},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"|"+tt.subject, func(t *testing.T) {
			assert.Equal(t, tt.expected, MatchSubject(tt.pattern, tt.subject))
		})
	}
}

func TestNormalizeIssuerConfig(t *testing.T) {
	valid := func() IssuerConfig {
		return IssuerConfig{
			Issuer:   "https://token.actions.githubusercontent.com",
			Audience: testAudience,
			Subject:  "repo:example/app:*",
		}
	}

	t.Run("valid with discovery", func(t *testing.T) {
		cfg := valid()
		cfg.Issuer = "  " + cfg.Issuer + "  "
		require.NoError(t, NormalizeIssuerConfig(&cfg))
		require.Equal(t, "https://token.actions.githubusercontent.com", cfg.Issuer)
	})

	t.Run("valid with a JWKS URL and a non-URL issuer", func(t *testing.T) {
		cfg := valid()
		cfg.Issuer = "kubernetes/serviceaccount"
		cfg.JWKSURL = "https://kubernetes.example.com/openid/v1/jwks"
		require.NoError(t, NormalizeIssuerConfig(&cfg))
	})

	tests := []struct {
		name   string
		mutate func(cfg *IssuerConfig)
		errMsg string
	}{
		{name: "missing issuer", mutate: func(cfg *IssuerConfig) { cfg.Issuer = " " }, errMsg: "issuer is required"},
		{name: "missing audience", mutate: func(cfg *IssuerConfig) { cfg.Audience = "" }, errMsg: "audience is required"},
		{name: "missing subject", mutate: func(cfg *IssuerConfig) { cfg.Subject = "" }, errMsg: "subject is required"},
		{name: "wildcard subject", mutate: func(cfg *IssuerConfig) { cfg.Subject = "**" }, errMsg: "only of wildcards"},
		{name: "control characters", mutate: func(cfg *IssuerConfig) { cfg.Subject = "a\nb" }, errMsg: "invalid characters"},
		{name: "subject too long", mutate: func(cfg *IssuerConfig) { cfg.Subject = strings.Repeat("a", MaxSubjectLength+1) }, errMsg: "at most"},
		{name: "http issuer", mutate: func(cfg *IssuerConfig) { cfg.Issuer = "http://issuer.example.com" }, errMsg: "scheme must be https"},
		{name: "non-URL issuer without JWKS URL", mutate: func(cfg *IssuerConfig) { cfg.Issuer = "kubernetes/serviceaccount" }, errMsg: "OpenID Connect discovery"},
		{name: "issuer with query", mutate: func(cfg *IssuerConfig) { cfg.Issuer += "?a=b" }, errMsg: "query string"},
		{name: "http JWKS URL", mutate: func(cfg *IssuerConfig) { cfg.JWKSURL = "http://issuer.example.com/jwks" }, errMsg: "scheme must be https"},
		{name: "JWKS URL with credentials", mutate: func(cfg *IssuerConfig) { cfg.JWKSURL = "https://user:pass@issuer.example.com/jwks" }, errMsg: "credentials"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := valid()
			tt.mutate(&cfg)
			err := NormalizeIssuerConfig(&cfg)
			require.ErrorContains(t, err, tt.errMsg)
		})
	}
}

func TestPeekClaims(t *testing.T) {
	iss := NewTestIssuer(t)
	token := iss.Token(testSubject, testAudience)

	claims, err := PeekClaims(token)
	require.NoError(t, err)
	require.Equal(t, iss.URL, claims.Issuer)
	require.Equal(t, testSubject, claims.Subject)
	require.Equal(t, []string{testAudience}, claims.Audience)

	_, err = PeekClaims("not-a-token")
	require.ErrorIs(t, err, ErrInvalidToken)

	_, err = PeekClaims(strings.Repeat("a", MaxTokenSize+1))
	require.ErrorIs(t, err, ErrInvalidToken)
}

func newTestVerifier(t *testing.T, iss *TestIssuer) *Verifier {
	t.Helper()

	v := NewVerifier(NewVerifierOptions{HTTPClient: iss.HTTPClient()})
	closeOnCleanup(t, v)

	return v
}

// closeOnCleanup closes the verifier when the test ends
// It can't use t.Context(), which is canceled before cleanup functions run: Close would return right away and leave the JWKS cache's workers running into later tests
func closeOnCleanup(t *testing.T, v *Verifier) {
	t.Helper()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		err := v.Close(ctx)
		require.NoError(t, err)
	})
}

func TestVerifierVerify(t *testing.T) {
	iss := NewTestIssuer(t)
	v := newTestVerifier(t, iss)

	cfg := IssuerConfig{
		Issuer:   iss.URL,
		Audience: testAudience,
		Subject:  "repo:example/app:ref:refs/tags/*",
	}

	t.Run("valid token with OIDC discovery", func(t *testing.T) {
		token := iss.Token(testSubject, testAudience, func(b *jwt.Builder) {
			b.JwtID("jti-1")
		})
		claims, err := v.Verify(t.Context(), token, cfg)
		require.NoError(t, err)
		require.Equal(t, iss.URL, claims.Issuer)
		require.Equal(t, testSubject, claims.Subject)
		require.Equal(t, "jti-1", claims.JwtID)
	})

	t.Run("valid token with an explicit JWKS URL", func(t *testing.T) {
		explicit := cfg
		explicit.JWKSURL = iss.JWKSURL()
		_, err := v.Verify(t.Context(), iss.Token(testSubject, testAudience), explicit)
		require.NoError(t, err)
	})

	t.Run("audience among several", func(t *testing.T) {
		token := iss.Token(testSubject, testAudience, func(b *jwt.Builder) {
			b.Audience([]string{"other", testAudience})
		})
		_, err := v.Verify(t.Context(), token, cfg)
		require.NoError(t, err)
	})

	rejected := []struct {
		name  string
		token func() string
	}{
		{
			name:  "wrong audience",
			token: func() string { return iss.Token(testSubject, "https://other.example.com") },
		},
		{
			name:  "subject does not match",
			token: func() string { return iss.Token("repo:example/app:ref:refs/heads/main", testAudience) },
		},
		{
			name: "wrong issuer",
			token: func() string {
				return iss.Token(testSubject, testAudience, func(b *jwt.Builder) {
					b.Issuer(iss.URL + "/other")
				})
			},
		},
		{
			name: "expired",
			token: func() string {
				return iss.Token(testSubject, testAudience, func(b *jwt.Builder) {
					b.IssuedAt(time.Now().Add(-time.Hour))
					b.Expiration(time.Now().Add(-10 * time.Minute))
				})
			},
		},
		{
			name: "not yet valid",
			token: func() string {
				return iss.Token(testSubject, testAudience, func(b *jwt.Builder) {
					b.NotBefore(time.Now().Add(10 * time.Minute))
				})
			},
		},
		{
			name: "missing expiration",
			token: func() string {
				return SignTestToken(t, iss.CurrentKey(), jwt.NewBuilder().
					Issuer(iss.URL).
					Subject(testSubject).
					Audience([]string{testAudience}))
			},
		},
		{
			name: "signed by a key that isn't published",
			token: func() string {
				// Same key ID as the published key, but a different key
				key := NewTestSigningKey(t, "key-1")
				return SignTestToken(t, key, jwt.NewBuilder().
					Issuer(iss.URL).
					Subject(testSubject).
					Audience([]string{testAudience}).
					Expiration(time.Now().Add(time.Minute)))
			},
		},
		{
			name: "unsigned",
			token: func() string {
				header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"key-1"}`))
				payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"` + iss.URL + `","sub":"` + testSubject + `","aud":"` + testAudience + `","exp":9999999999}`))
				return header + "." + payload + ".c2ln"
			},
		},
	}

	for _, tt := range rejected {
		t.Run(tt.name, func(t *testing.T) {
			_, err := v.Verify(t.Context(), tt.token(), cfg)
			require.ErrorIs(t, err, ErrInvalidToken)
		})
	}
}

func TestVerifierRejectsSymmetricKeys(t *testing.T) {
	iss := NewTestIssuer(t)
	v := newTestVerifier(t, iss)

	// Publish a symmetric key in the JWKS: anyone can read it, so tokens signed with it must never be accepted
	secret := []byte("0123456789abcdef0123456789abcdef")
	hmacKey, err := jwk.Import[jwk.Key](secret)
	require.NoError(t, err)
	require.NoError(t, hmacKey.Set(jwk.KeyIDKey, "hmac"))
	require.NoError(t, hmacKey.Set(jwk.AlgorithmKey, jwa.HS256()))
	iss.PublishExtraKey(hmacKey)

	tok, err := jwt.NewBuilder().
		Issuer(iss.URL).
		Subject(testSubject).
		Audience([]string{testAudience}).
		Expiration(time.Now().Add(time.Minute)).
		Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256(), hmacKey))
	require.NoError(t, err)

	_, err = v.Verify(t.Context(), string(signed), IssuerConfig{
		Issuer:   iss.URL,
		Audience: testAudience,
		Subject:  testSubject,
	})
	require.ErrorIs(t, err, ErrInvalidToken)
}

func TestVerifierKeyRotation(t *testing.T) {
	iss := NewTestIssuer(t)
	v := newTestVerifier(t, iss)

	cfg := IssuerConfig{
		Issuer:   iss.URL,
		Audience: testAudience,
		Subject:  testSubject,
		JWKSURL:  iss.JWKSURL(),
	}

	// Use a fake clock, and check when the verifier last forced a refresh of the JWKS
	// Counting the issuer's JWKS fetches would be racy: the cache also fetches the JWKS in the background right after it's registered
	now := time.Now()
	v.now = func() time.Time {
		return now
	}
	lastForcedRefresh := func() time.Time {
		v.lock.Lock()
		defer v.lock.Unlock()

		entry, ok := v.jwks[iss.JWKSURL()]
		require.True(t, ok)
		return entry.lastForcedRefresh
	}

	// The first token forces a refresh, since the JWKS hasn't been fetched yet
	_, err := v.Verify(t.Context(), iss.Token(testSubject, testAudience), cfg)
	require.NoError(t, err)
	require.Equal(t, now, lastForcedRefresh())
	firstRefresh := now

	// Tokens signed with a cached key don't force a refresh
	now = now.Add(time.Hour)
	_, err = v.Verify(t.Context(), iss.Token(testSubject, testAudience), cfg)
	require.NoError(t, err)
	require.Equal(t, firstRefresh, lastForcedRefresh())

	// Tokens signed with a new key force a refresh, which fetches the new key
	iss.RotateKey("key-2")
	_, err = v.Verify(t.Context(), iss.Token(testSubject, testAudience), cfg)
	require.NoError(t, err)
	require.Equal(t, now, lastForcedRefresh())
	secondRefresh := now

	// Forced refreshes are rate-limited
	iss.RotateKey("key-3")
	now = now.Add(v.forcedRefreshInterval / 2)
	_, err = v.Verify(t.Context(), iss.Token(testSubject, testAudience), cfg)
	require.ErrorIs(t, err, ErrInvalidToken)
	require.Equal(t, secondRefresh, lastForcedRefresh())

	// Once the interval has passed, the next token forces a refresh again
	now = now.Add(v.forcedRefreshInterval)
	_, err = v.Verify(t.Context(), iss.Token(testSubject, testAudience), cfg)
	require.NoError(t, err)
	require.Equal(t, now, lastForcedRefresh())
}

func TestVerifierDiscoveryIssuerMismatch(t *testing.T) {
	iss := NewTestIssuer(t)
	iss.SetDiscoveryIssuer("https://someone-else.example.com")
	v := newTestVerifier(t, iss)

	_, err := v.Verify(t.Context(), iss.Token(testSubject, testAudience), IssuerConfig{
		Issuer:   iss.URL,
		Audience: testAudience,
		Subject:  testSubject,
	})
	require.ErrorIs(t, err, ErrKeyFetch)
	require.ErrorContains(t, err, "someone-else")
}

func TestVerifierUnreachableJWKS(t *testing.T) {
	iss := NewTestIssuer(t)
	v := newTestVerifier(t, iss)

	_, err := v.Verify(t.Context(), iss.Token(testSubject, testAudience), IssuerConfig{
		Issuer:   iss.URL,
		Audience: testAudience,
		Subject:  testSubject,
		JWKSURL:  iss.URL + "/missing",
	})
	require.ErrorIs(t, err, ErrKeyFetch)
}

func TestVerifierClose(t *testing.T) {
	iss := NewTestIssuer(t)
	v := NewVerifier(NewVerifierOptions{HTTPClient: iss.HTTPClient()})

	// Closing a verifier that was never used is a no-op
	err := v.Close(t.Context())
	require.NoError(t, err)
	err = v.Close(t.Context())
	require.NoError(t, err)

	_, err = v.Verify(t.Context(), iss.Token(testSubject, testAudience), IssuerConfig{
		Issuer:   iss.URL,
		Audience: testAudience,
		Subject:  testSubject,
		JWKSURL:  iss.JWKSURL(),
	})
	require.ErrorContains(t, err, "closed")
}

func TestVerifierConcurrentRequests(t *testing.T) {
	const concurrency = 20

	verifyConcurrently := func(t *testing.T, v *Verifier, token string, cfg IssuerConfig) {
		t.Helper()

		errs := make(chan error, concurrency)
		start := make(chan struct{})
		for range concurrency {
			go func() {
				<-start
				_, rErr := v.Verify(t.Context(), token, cfg)
				errs <- rErr
			}()
		}
		close(start)

		for range concurrency {
			require.NoError(t, <-errs)
		}
	}

	iss := NewTestIssuer(t)
	cfg := IssuerConfig{
		Issuer:   iss.URL,
		Audience: testAudience,
		Subject:  testSubject,
	}

	t.Run("first use of an issuer", func(t *testing.T) {
		v := newTestVerifier(t, iss)
		verifyConcurrently(t, v, iss.Token(testSubject, testAudience), cfg)
	})

	t.Run("after the issuer rotates its keys", func(t *testing.T) {
		v := newTestVerifier(t, iss)
		now := time.Now()
		v.now = func() time.Time {
			return now
		}

		_, err := v.Verify(t.Context(), iss.Token(testSubject, testAudience), cfg)
		require.NoError(t, err)

		// The first use forced a refresh, so wait for the rate limit to allow another one
		now = now.Add(v.forcedRefreshInterval)
		iss.RotateKey("key-rotated")
		verifyConcurrently(t, v, iss.Token(testSubject, testAudience), cfg)
	})
}

func TestVerifierCloseWhileInUse(t *testing.T) {
	iss := NewTestIssuer(t)
	cfg := IssuerConfig{
		Issuer:   iss.URL,
		Audience: testAudience,
		Subject:  testSubject,
		JWKSURL:  iss.JWKSURL(),
	}

	// Tokens signed with a key that the issuer doesn't publish force a refresh of the JWKS every time, since the rate limit is disabled below
	tokens := []string{
		iss.Token(testSubject, testAudience),
		SignTestToken(t, NewTestSigningKey(t, "unpublished-key"), jwt.NewBuilder().
			Issuer(iss.URL).
			Subject(testSubject).
			Audience([]string{testAudience}).
			Expiration(time.Now().Add(time.Hour)),
		),
	}

	for range 20 {
		v := NewVerifier(NewVerifierOptions{HTTPClient: iss.HTTPClient()})
		v.forcedRefreshInterval = 0

		// Verify tokens until the verifier is closed
		var wg sync.WaitGroup
		for i := range 10 {
			wg.Go(func() {
				for {
					ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
					_, err := v.Verify(ctx, tokens[i%len(tokens)], cfg)
					cancel()
					if err != nil && strings.Contains(err.Error(), "verifier is closed") {
						return
					}
				}
			})
		}

		time.Sleep(20 * time.Millisecond)
		require.NoError(t, v.Close(t.Context()))
		wg.Wait()
	}
}
