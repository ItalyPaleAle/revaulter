package server

import (
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/italypaleale/revaulter/pkg/config"
)

// AllowIpMiddleware is a middleware that allows requests from certain IPs only
func (s *Server) AllowIpMiddleware() (gin.HandlerFunc, error) {
	// Get the list of IPs and ranges that are allowed
	conf := config.Get().AllowedIps
	if len(conf) == 0 || (len(conf) == 1 && conf[0] == "") {
		// Allow all IPs, so do nothing
		return func(c *gin.Context) {}, nil
	}
	ips := []net.IP{}
	ipRanges := []*net.IPNet{}
	for _, v := range conf {
		// Check if we have a single IP or a range
		if strings.ContainsRune(v, '/') {
			_, r, err := net.ParseCIDR(v)
			if err != nil {
				return nil, errors.New("invalid IP range: " + v)
			}
			ipRanges = append(ipRanges, r)
		} else {
			ip := net.ParseIP(v)
			if ip == nil {
				return nil, errors.New("invalid IP: " + v)
			}
			ips = append(ips, ip)
		}
	}

	// Return the middleware
	return func(c *gin.Context) {
		// Get the IP connecting
		ip := net.ParseIP(c.RemoteIP())
		if ip == nil {
			_ = c.Error(errors.New("invalid remote IP address"))
			c.AbortWithStatusJSON(http.StatusInternalServerError, InternalServerError)
			return
		}

		// Check if the IP is in the allowlists
		for _, e := range ips {
			if e.Equal(ip) {
				// Can continue
				return
			}
		}
		for _, e := range ipRanges {
			if e.Contains(ip) {
				// Can continue
				return
			}
		}

		// If we reach this point, the IP is not in the allow-list
		_ = c.Error(errors.New("IP not allowed"))
		c.AbortWithStatusJSON(http.StatusForbidden, ErrorResponse("This client's IP is not allowed to perform this request"))
	}, nil
}
