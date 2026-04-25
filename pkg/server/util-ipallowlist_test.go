package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type testClientIPContext struct {
	clientIP string
}

func (c testClientIPContext) ClientIP() string {
	return c.clientIP
}

func TestClientIPAllowed(t *testing.T) {
	tests := []struct {
		name       string
		clientIP   string
		allowedIPs []string
		expected   bool
	}{
		{
			name:       "allowlist empty allows any IPv4 client",
			clientIP:   "198.51.100.10",
			allowedIPs: nil,
			expected:   true,
		},
		{
			name:       "exact IPv4 match allowed",
			clientIP:   "198.51.100.10",
			allowedIPs: []string{"198.51.100.10"},
			expected:   true,
		},
		{
			name:       "IPv4 CIDR match allowed",
			clientIP:   "198.51.100.42",
			allowedIPs: []string{"198.51.100.0/24"},
			expected:   true,
		},
		{
			name:       "IPv4 outside CIDR denied",
			clientIP:   "198.51.101.42",
			allowedIPs: []string{"198.51.100.0/24"},
			expected:   false,
		},
		{
			name:       "exact IPv6 match allowed",
			clientIP:   "2001:db8::10",
			allowedIPs: []string{"2001:db8::10"},
			expected:   true,
		},
		{
			name:       "IPv6 CIDR match allowed",
			clientIP:   "2001:db8:abcd::1234",
			allowedIPs: []string{"2001:db8:abcd::/48"},
			expected:   true,
		},
		{
			name:       "IPv6 outside CIDR denied",
			clientIP:   "2001:db8:abce::1234",
			allowedIPs: []string{"2001:db8:abcd::/48"},
			expected:   false,
		},
		{
			name:       "invalid client IP denied when allowlist exists",
			clientIP:   "not-an-ip",
			allowedIPs: []string{"198.51.100.0/24", "2001:db8::/32"},
			expected:   false,
		},
		{
			name:       "invalid allowlist entries are skipped when a later IPv6 entry matches",
			clientIP:   "2001:db8::25",
			allowedIPs: []string{"bad-entry", "2001:db8::/64"},
			expected:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := testClientIPContext{clientIP: test.clientIP}

			allowed := clientIPAllowed(ctx, test.allowedIPs)

			assert.Equal(t, test.expected, allowed)
		})
	}
}
