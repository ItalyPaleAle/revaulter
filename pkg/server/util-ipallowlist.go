package server

import (
	"net"
)

// clientIPAllowed checks if a client IP is allowed based on an allowlist
func clientIPAllowed(clientIP string, allowedIPs []string) bool {
	if len(allowedIPs) == 0 {
		return true
	}

	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}

	for _, entry := range allowedIPs {
		_, network, err := net.ParseCIDR(entry)
		if err == nil {
			if network.Contains(ip) {
				return true
			}
			continue
		}

		allowedIP := net.ParseIP(entry)
		if allowedIP != nil && allowedIP.Equal(ip) {
			return true
		}
	}

	return false
}
