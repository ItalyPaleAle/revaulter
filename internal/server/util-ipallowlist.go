package server

import (
	"net"
)

type contextClientIP interface {
	ClientIP() string
}

// clientIPAllowed checks if a client IP is allowed based on an allowlist
func clientIPAllowed(c contextClientIP, allowedIPs []string) bool {
	// No allowlist - everything is allowed
	if len(allowedIPs) == 0 {
		return true
	}

	// Get the IP
	ip := net.ParseIP(c.ClientIP())
	if ip == nil {
		return false
	}

	// Check if the IP is allowed
	for _, entry := range allowedIPs {
		// Try CIDR first
		_, network, err := net.ParseCIDR(entry)
		if err == nil {
			if network.Contains(ip) {
				return true
			}
			continue
		}

		// Try IP
		allowedIP := net.ParseIP(entry)
		if allowedIP != nil && allowedIP.Equal(ip) {
			return true
		}
	}

	return false
}
