package requestjwt

import (
	"io"
	"net/http"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdkTrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func TestIsPublicAddress(t *testing.T) {
	tests := []struct {
		addr     string
		expected bool
	}{
		{addr: "8.8.8.8", expected: true},
		{addr: "140.82.112.3", expected: true},
		{addr: "2606:4700:4700::1111", expected: true},
		{addr: "10.1.2.3", expected: false},
		{addr: "172.16.0.1", expected: false},
		{addr: "192.168.1.1", expected: false},
		{addr: "127.0.0.1", expected: false},
		{addr: "169.254.169.254", expected: false},
		{addr: "100.64.0.1", expected: false},
		{addr: "0.0.0.0", expected: false},
		{addr: "0.1.2.3", expected: false},
		{addr: "198.18.0.1", expected: false},
		{addr: "240.0.0.1", expected: false},
		{addr: "255.255.255.255", expected: false},
		{addr: "224.0.0.1", expected: false},
		{addr: "::1", expected: false},
		{addr: "::", expected: false},
		{addr: "fe80::1", expected: false},
		{addr: "fd00::1", expected: false},
		{addr: "64:ff9b::a01:203", expected: false},
		{addr: "ff02::1", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			assert.Equal(t, tt.expected, isPublicAddress(netip.MustParseAddr(tt.addr)))
		})
	}
}

func TestForbidPrivateAddressesUnmapsIPv4(t *testing.T) {
	// IPv4-mapped IPv6 addresses are checked as the IPv4 address they map to
	err := forbidPrivateAddresses("tcp6", "[::ffff:127.0.0.1]:443", nil)
	require.ErrorContains(t, err, "non-public address 127.0.0.1")

	err = forbidPrivateAddresses("tcp4", "8.8.8.8:443", nil)
	require.NoError(t, err)
}

func TestVerifierRejectsRedirects(t *testing.T) {
	t.Run("JWKS", func(t *testing.T) {
		iss := NewTestIssuer(t)
		iss.Redirect("/moved-jwks", "/jwks")
		v := newTestVerifier(t, iss)

		_, err := v.Verify(t.Context(), iss.Token(testSubject, testAudience), IssuerConfig{
			Issuer:   iss.URL,
			Audience: testAudience,
			Subject:  testSubject,
			JWKSURL:  iss.URL + "/moved-jwks",
		})
		require.ErrorIs(t, err, ErrKeyFetch)
		require.ErrorContains(t, err, "redirects are not allowed")
	})

	t.Run("discovery document", func(t *testing.T) {
		iss := NewTestIssuer(t)
		iss.Redirect("/.well-known/openid-configuration", "/somewhere-else")
		v := newTestVerifier(t, iss)

		_, err := v.Verify(t.Context(), iss.Token(testSubject, testAudience), IssuerConfig{
			Issuer:   iss.URL,
			Audience: testAudience,
			Subject:  testSubject,
		})
		require.ErrorIs(t, err, ErrKeyFetch)
		require.ErrorContains(t, err, "redirects are not allowed")
	})
}

func TestVerifierForbidsPrivateAddressesByDefault(t *testing.T) {
	// The test issuer listens on a loopback address
	iss := NewTestIssuer(t)
	v := NewVerifier(NewVerifierOptions{
		HTTPClient: NewHTTPClient(HTTPClientOptions{
			TLSConfig: iss.TLSConfig(),
		}),
	})
	t.Cleanup(func() {
		_ = v.Close(t.Context())
	})

	cfg := IssuerConfig{
		Issuer:   iss.URL,
		Audience: testAudience,
		Subject:  testSubject,
	}

	// Both the discovery document and the JWKS are refused
	_, err := v.Verify(t.Context(), iss.Token(testSubject, testAudience), cfg)
	require.ErrorIs(t, err, ErrKeyFetch)
	require.ErrorContains(t, err, "non-public address")

	cfg.JWKSURL = iss.JWKSURL()
	_, err = v.Verify(t.Context(), iss.Token(testSubject, testAudience), cfg)
	require.ErrorIs(t, err, ErrKeyFetch)
	require.ErrorContains(t, err, "non-public address")
}

func TestNewHTTPClientTracing(t *testing.T) {
	// Record the spans of the global tracer provider
	recorder := tracetest.NewSpanRecorder()
	provider := sdkTrace.NewTracerProvider(sdkTrace.WithSpanProcessor(recorder))
	prevProvider := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	t.Cleanup(func() {
		otel.SetTracerProvider(prevProvider)
		_ = provider.Shutdown(t.Context())
	})

	iss := NewTestIssuer(t)
	client := iss.HTTPClient()

	ctx, parent := provider.Tracer("test").Start(t.Context(), "parent")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, iss.JWKSURL(), nil)
	require.NoError(t, err)
	res, err := client.Do(req)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	parent.End()

	// The request's span is a child of the span in the request's context
	var spans []sdkTrace.ReadOnlySpan
	for _, span := range recorder.Ended() {
		if span.SpanKind() == trace.SpanKindClient {
			spans = append(spans, span)
		}
	}
	require.Len(t, spans, 1)
	require.Equal(t, parent.SpanContext().SpanID(), spans[0].Parent().SpanID())
	require.Equal(t, parent.SpanContext().TraceID(), spans[0].SpanContext().TraceID())
}
