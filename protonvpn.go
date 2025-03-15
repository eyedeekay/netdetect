// Package netdetect provides utilities for detecting and identifying specific
// network interfaces on a system.
package netdetect

import (
	"fmt"
	"net"
	"strings"
)

// ProtonVPNIPPrefix defines the known IPv4 prefix for ProtonVPN addresses
// ProtonVPN typically uses 10.2.0.0/16 for standard servers
const ProtonVPNIPPrefix = "10.2."

// Common ProtonVPN interface name patterns
var protonVPNPatterns = []string{
	"proton",
	"pvpn",
	"protonvpn",
	"tun-proton",
}

// FindProtonVPNInterfaces returns a slice of network interfaces that are
// identified as ProtonVPN tunnel interfaces. It uses multiple detection
// methods including interface naming patterns and IP address assignments.
//
// Returns:
//   - []net.Interface: Slice of identified ProtonVPN interfaces
//   - error: Any error encountered during interface detection
//
// The function may return an empty slice if no ProtonVPN interfaces are found.
func FindProtonVPNInterfaces() ([]net.Interface, error) {
	// Get all network interfaces
	allInterfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to list network interfaces: %w", err)
	}

	var protonVPNInterfaces []net.Interface

	// Iterate through interfaces to identify ProtonVPN ones
	for _, iface := range allInterfaces {
		isProtonVPN, err := isProtonVPNInterface(&iface)
		if err != nil {
			// Log the error but continue checking other interfaces
			continue
		}
		if isProtonVPN {
			protonVPNInterfaces = append(protonVPNInterfaces, iface)
		}
	}

	return protonVPNInterfaces, nil
}

// isProtonVPNInterface checks if the given interface is a ProtonVPN interface
// using multiple detection methods.
func isProtonVPNInterface(iface *net.Interface) (bool, error) {
	if iface == nil {
		return false, fmt.Errorf("nil interface provided")
	}

	// Check interface name patterns
	for _, pattern := range protonVPNPatterns {
		if strings.Contains(strings.ToLower(iface.Name), pattern) {
			return true, nil
		}
	}

	// Get interface addresses
	addrs, err := iface.Addrs()
	if err != nil {
		return false, fmt.Errorf("failed to get addresses for interface %s: %w", iface.Name, err)
	}

	// Check for ProtonVPN IP range
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ipNet.IP.To4() != nil && strings.HasPrefix(ipNet.IP.String(), ProtonVPNIPPrefix) {
			return true, nil
		}
	}

	return false, nil
}
