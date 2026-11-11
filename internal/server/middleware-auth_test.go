package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-contrib/location/v2"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/internal/config"
)

func TestCookieSecurityForOrigins(t *testing.T) {
	tests := []struct {
		name             string
		origins          []string
		wantAlwaysSecure bool
		wantMixed        bool
	}{
		{name: "only https origins", origins: []string{"https://auth.example.com", "https://console.example.com"}, wantAlwaysSecure: true},
		{name: "only an http localhost origin", origins: []string{"http://localhost:8080"}},
		{name: "https and http localhost origins", origins: []string{"https://auth.example.com", "http://localhost:8080"}, wantMixed: true},
		{name: "scheme is case-insensitive", origins: []string{"HTTPS://auth.example.com"}, wantAlwaysSecure: true},
		{name: "non-web origins are ignored", origins: []string{"https://auth.example.com", "android:apk-key-hash:abc123"}, wantAlwaysSecure: true},
		{name: "only non-web origins", origins: []string{"android:apk-key-hash:abc123"}},
		{name: "no origins", origins: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alwaysSecure, mixed := cookieSecurityForOrigins(tt.origins)
			assert.Equal(t, tt.wantAlwaysSecure, alwaysSecure)
			assert.Equal(t, tt.wantMixed, mixed)
		})
	}
}

// The decision must use the same origins that WebAuthn checks, including baseUrl and with wildcards dropped
func TestCookieSecurityUsesWebAuthnOrigins(t *testing.T) {
	tests := []struct {
		name             string
		baseURL          string
		origins          []string
		wantAlwaysSecure bool
		wantMixed        bool
	}{
		{name: "https base URL", baseURL: "https://auth.example.com", wantAlwaysSecure: true},
		{name: "https base URL with a wildcard origin", baseURL: "https://auth.example.com", origins: []string{"*"}, wantAlwaysSecure: true},
		{name: "localhost base URL", baseURL: "http://localhost:8080"},
		{name: "localhost base URL with an https origin", baseURL: "http://localhost:8080", origins: []string{"https://auth.example.com"}, wantMixed: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(config.SetTestConfig(map[string]any{
				"baseUrl":         tt.baseURL,
				"webauthnRpId":    "example.com",
				"webauthnRpName":  "Revaulter",
				"webauthnOrigins": tt.origins,
			}))

			wa, err := (&Server{}).initWebAuthn()
			require.NoError(t, err)

			alwaysSecure, mixed := cookieSecurityForOrigins(wa.Config.RPOrigins)
			assert.Equal(t, tt.wantAlwaysSecure, alwaysSecure)
			assert.Equal(t, tt.wantMixed, mixed)
		})
	}
}

func TestSessionCookieFor(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name                string
		cookiesAlwaysSecure bool
		forwardedProto      string
		wantName            string
		wantPath            string
	}{
		// A TLS-terminating proxy that doesn't send X-Forwarded-Proto must still get Secure cookies when every origin is https
		{name: "https origins without a forwarded scheme", cookiesAlwaysSecure: true, wantName: sessionCookieNameSecure, wantPath: "/"},
		{name: "https origins with a forwarded http scheme", cookiesAlwaysSecure: true, forwardedProto: "http", wantName: sessionCookieNameSecure, wantPath: "/"},
		{name: "localhost origin over plain http", wantName: sessionCookieNameInsecure, wantPath: "/v2"},
		{name: "localhost origin behind a TLS proxy", forwardedProto: "https", wantName: sessionCookieNameSecure, wantPath: "/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{cookiesAlwaysSecure: tt.cookiesAlwaysSecure}

			var gotName, gotPath string
			var gotSecure bool
			router := gin.New()
			router.Use(location.Default())
			router.GET("/", func(c *gin.Context) {
				gotName, gotPath = s.sessionCookieFor(c)
				gotSecure = s.secureCookie(c)
			})

			req := httptest.NewRequest(http.MethodGet, "http://revaulter.example.com/", nil)
			if tt.forwardedProto != "" {
				req.Header.Set("X-Forwarded-Proto", tt.forwardedProto)
			}
			router.ServeHTTP(httptest.NewRecorder(), req)

			assert.Equal(t, tt.wantName, gotName)
			assert.Equal(t, tt.wantPath, gotPath)
			assert.Equal(t, tt.wantName == sessionCookieNameSecure, gotSecure)
		})
	}
}

// Without the location middleware the request scheme is unknown, which must not panic
func TestSecureCookieWithoutLocation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	assert.False(t, (&Server{}).secureCookie(c))
	assert.True(t, (&Server{cookiesAlwaysSecure: true}).secureCookie(c))
}
