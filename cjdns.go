package netdetect

import (
	"fmt"
	"net"
	"strings"
)

// CJDNSIPPrefix defines the known IPv6 prefix for CJDNS addresses
// CJDNS uses fc00::/8 for its network addresses
const CJDNSIPPrefix = "fc00:"

// Common CJDNS interface name patterns
var cjdnsPatterns = []string{
	"cjdns",
	"tun-cjdns",
	"cjd",
	"hyperboria",
}

// FindCJDNSInterfaces returns a slice of network interfaces that are
// identified as CJDNS tunnel interfaces. It uses multiple detection
// methods including interface naming patterns and IPv6 address assignments.
//
// Returns:
//   - []net.Interface: Slice of identified CJDNS interfaces
//   - error: Any error encountered during interface detection
//
// The function may return an empty slice if no CJDNS interfaces are found.
func FindCJDNSInterfaces() ([]net.Interface, error) {
	// Get all network interfaces
	allInterfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to list network interfaces: %w", err)
	}

	var cjdnsInterfaces []net.Interface

	// Iterate through interfaces to identify CJDNS ones
	for _, iface := range allInterfaces {
		isCJDNS, err := isCJDNSInterface(&iface)
		if err != nil {
			// Log the error but continue checking other interfaces
			continue
		}
		if isCJDNS {
			cjdnsInterfaces = append(cjdnsInterfaces, iface)
		}
	}

	return cjdnsInterfaces, nil
}

// isCJDNSInterface checks if the given interface is a CJDNS interface
// using multiple detection methods.
func isCJDNSInterface(iface *net.Interface) (bool, error) {
	if iface == nil {
		return false, fmt.Errorf("nil interface provided")
	}

	// Check interface name patterns
	for _, pattern := range cjdnsPatterns {
		if strings.Contains(strings.ToLower(iface.Name), pattern) {
			return true, nil
		}
	}

	// Get interface addresses
	addrs, err := iface.Addrs()
	if err != nil {
		return false, fmt.Errorf("failed to get addresses for interface %s: %w", iface.Name, err)
	}

	// Check for CJDNS IPv6 range
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		// CJDNS uses IPv6, so we specifically check for IPv6 addresses
		if ipNet.IP.To4() == nil && strings.HasPrefix(ipNet.IP.String(), CJDNSIPPrefix) {
			return true, nil
		}
	}

	return false, nil
}
