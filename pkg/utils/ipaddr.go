package utils

import (
	"net"
)

// Pre-parsed CIDR ranges used by IsPrivateIP
// Parsing once at package init avoids repeating the work on every call
var (
	ipAllowRanges   []*net.IPNet
	ipPrivateRanges []*net.IPNet
)

func init() {
	// Explicit allow-list overrides the block list
	// CGNAT (RFC 6598) 100.64.0.0/10 is widely used as legitimate routable address space by Tailscale and similar overlays
	// fd7a:115c:a1e0::/48 is Tailscale's well-known ULA subset; it is nominally inside fc00::/7 but is used for legitimate cross-host traffic
	ipAllowRanges = mustParseCIDRs([]string{
		"100.64.0.0/10",
		"fd7a:115c:a1e0::/48",
	})

	ipPrivateRanges = mustParseCIDRs([]string{
		// IPv4 non-routable and private ranges
		"0.0.0.0/8",          // this host / current network (RFC 1122)
		"10.0.0.0/8",         // private-use (RFC 1918)
		"127.0.0.0/8",        // loopback (RFC 1122)
		"169.254.0.0/16",     // link-local (RFC 3927), covers AWS/GCP/Azure metadata 169.254.169.254
		"172.16.0.0/12",      // private-use (RFC 1918)
		"192.0.0.0/24",       // IETF protocol assignments (RFC 6890)
		"192.0.2.0/24",       // documentation TEST-NET-1 (RFC 5737)
		"192.168.0.0/16",     // private-use (RFC 1918)
		"198.18.0.0/15",      // benchmarking (RFC 2544)
		"198.51.100.0/24",    // documentation TEST-NET-2 (RFC 5737)
		"203.0.113.0/24",     // documentation TEST-NET-3 (RFC 5737)
		"224.0.0.0/4",        // multicast (RFC 5771)
		"240.0.0.0/4",        // reserved, class E (RFC 1112)
		"255.255.255.255/32", // limited broadcast (RFC 919)

		// IPv6 non-routable and private ranges
		"::/128",        // unspecified address
		"::1/128",       // loopback
		"2001:db8::/32", // documentation (RFC 3849)
		"fc00::/7",      // unique local address (RFC 4193); Tailscale subset carved out above
		"fe80::/10",     // link-local (RFC 4291)
		"ff00::/8",      // multicast (RFC 4291)
	})
}

// mustParseCIDRs parses each CIDR literal and panics on failure
// Only intended for package-init use with trusted string literals
func mustParseCIDRs(cidrs []string) []*net.IPNet {
	out := make([]*net.IPNet, len(cidrs))
	for i, c := range cidrs {
		_, network, err := net.ParseCIDR(c)
		if err != nil {
			panic("utils: invalid CIDR literal " + c + ": " + err.Error())
		}
		out[i] = network
	}
	return out
}

// IsPrivateIP returns true if ip is in a private, loopback, link-local, or otherwise non-routable range
// Addresses in the CGNAT range (100.64.0.0/10) and Tailscale ULA subset (fd7a:115c:a1e0::/48) are treated as routable, because they are used as legitimate cross-host address space by overlays like Tailscale
// A nil or zero-length ip yields false, matching the behavior of net.IPNet.Contains
func IsPrivateIP(ip net.IP) bool {
	// Normalize IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) to their IPv4 form so the v4 block list applies uniformly
	v4 := ip.To4()
	if v4 != nil {
		ip = v4
	}

	for _, network := range ipAllowRanges {
		if network.Contains(ip) {
			return false
		}
	}

	for _, network := range ipPrivateRanges {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
