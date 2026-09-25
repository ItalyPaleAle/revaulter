package requestjwt

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// errRedirectsNotAllowed is returned when an issuer responds with a redirect
var errRedirectsNotAllowed = errors.New("redirects are not allowed when fetching OIDC discovery documents and JWKS")

// nonPublicPrefixes are ranges that aren't publicly routable, in addition to the ones netip.Addr's methods detect
var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
}

// HTTPClientOptions contains the options for NewHTTPClient
type HTTPClientOptions struct {
	// If true, connections to private, loopback, link-local, and other non-public addresses are allowed
	// By default, they are refused
	AllowPrivateAddresses bool
	// Optional TLS configuration
	TLSConfig *tls.Config
}

// NewHTTPClient returns an HTTP client for fetching OIDC discovery documents and JWKS
// The URLs it fetches are configured by users, so it never follows redirects
func NewHTTPClient(opts HTTPClientOptions) *http.Client {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	if !opts.AllowPrivateAddresses {
		// The check runs on the resolved address right before connecting, so DNS names that resolve to a private address are refused too
		dialer.Control = forbidPrivateAddresses
	}

	tlsConfig := opts.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	} else {
		tlsConfig = tlsConfig.Clone()
	}

	// Enforce TLS 1.2 or higher
	tlsConfig.MinVersion = max(tlsConfig.MinVersion, tls.VersionTLS12)

	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: otelhttp.NewTransport(&http.Transport{
			Proxy:                 nil,
			DialContext:           dialer.DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          10,
			MaxIdleConnsPerHost:   2,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
			TLSClientConfig:       tlsConfig,
		}),
		// A redirect could point to a URL the user couldn't have configured, such as a plain HTTP one
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errRedirectsNotAllowed
		},
	}
}

// forbidPrivateAddresses is a net.Dialer control function that refuses connections to non-public addresses
func forbidPrivateAddresses(_ string, address string, _ syscall.RawConn) error {
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("invalid address %q: %w", address, err)
	}

	addr := addrPort.Addr().Unmap()
	if !isPublicAddress(addr) {
		return fmt.Errorf("connections to the non-public address %s are not allowed", addr)
	}

	return nil
}

// isPublicAddress returns true if addr is a publicly-routable unicast address
// Loopback, link-local, multicast, and unspecified addresses aren't global unicast
func isPublicAddress(addr netip.Addr) bool {
	if !addr.IsValid() || !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return false
	}

	for _, p := range nonPublicPrefixes {
		if p.Contains(addr) {
			return false
		}
	}

	return true
}
