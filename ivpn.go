// Package netdetect provides utilities for detecting and identifying specific
// network interfaces on a system.
package netdetect

import (
	"fmt"
	"net"
	"strings"
)

// IVPNIPPrefix defines the known IPv4 prefix for IVPN addresses
// IVPN typically uses 172.16.0.0/16 for its tunnel interfaces
const IVPNIPPrefix = "172.16."

// Common IVPN interface name patterns
var ivpnPatterns = []string{
	"ivpn",
	"tun-ivpn",
	"wg-ivpn",
}

// FindIVPNInterfaces returns a slice of network interfaces that are
// identified as IVPN tunnel interfaces. It uses multiple detection
// methods including interface naming patterns and IP address assignments.
//
// Returns:
//   - []net.Interface: Slice of identified IVPN interfaces
//   - error: Any error encountered during interface detection
//
// The function may return an empty slice if no IVPN interfaces are found.
func FindIVPNInterfaces() ([]net.Interface, error) {
	// Get all network interfaces
	allInterfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to list network interfaces: %w", err)
	}

	var ivpnInterfaces []net.Interface

	// Iterate through interfaces to identify IVPN ones
	for _, iface := range allInterfaces {
		isIVPN, err := isIVPNInterface(&iface)
		if err != nil {
			// Log the error but continue checking other interfaces
			continue
		}
		if isIVPN {
			ivpnInterfaces = append(ivpnInterfaces, iface)
		}
	}

	return ivpnInterfaces, nil
}

// isIVPNInterface checks if the given interface is an IVPN interface
// using multiple detection methods.
func isIVPNInterface(iface *net.Interface) (bool, error) {
	if iface == nil {
		return false, fmt.Errorf("nil interface provided")
	}

	// Check interface name patterns
	for _, pattern := range ivpnPatterns {
		if strings.Contains(strings.ToLower(iface.Name), pattern) {
			return true, nil
		}
	}

	// Get interface addresses
	addrs, err := iface.Addrs()
	if err != nil {
		return false, fmt.Errorf("failed to get addresses for interface %s: %w", iface.Name, err)
	}

	// Check for IVPN IP range
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ipNet.IP.To4() != nil && strings.HasPrefix(ipNet.IP.String(), IVPNIPPrefix) {
			return true, nil
		}
	}

	return false, nil
}
