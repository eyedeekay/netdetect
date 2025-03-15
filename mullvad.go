// Package netdetect provides utilities for detecting and identifying specific
// network interfaces on a system.
package netdetect

import (
	"fmt"
	"net"
	"strings"
)

// MullvadIPPrefix defines the known IPv4 prefix for Mullvad addresses
// Mullvad uses 10.64.0.0/10 for IPv4
const MullvadIPPrefix = "10.64."

// Common Mullvad interface name patterns
var mullvadPatterns = []string{
	"mullvad",
	"wg-mullvad",
	"mvd-",
}

// FindMullvadInterfaces returns a slice of network interfaces that are
// identified as Mullvad tunnel interfaces. It uses multiple detection
// methods including interface naming patterns and IP address assignments.
//
// Returns:
//   - []net.Interface: Slice of identified Mullvad interfaces
//   - error: Any error encountered during interface detection
//
// The function may return an empty slice if no Mullvad interfaces are found.
func FindMullvadInterfaces() ([]net.Interface, error) {
	// Get all network interfaces
	allInterfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to list network interfaces: %w", err)
	}

	var mullvadInterfaces []net.Interface

	// Iterate through interfaces to identify Mullvad ones
	for _, iface := range allInterfaces {
		isMullvad, err := isMullvadInterface(&iface)
		if err != nil {
			// Log the error but continue checking other interfaces
			continue
		}
		if isMullvad {
			mullvadInterfaces = append(mullvadInterfaces, iface)
		}
	}

	return mullvadInterfaces, nil
}

// isMullvadInterface checks if the given interface is a Mullvad interface
// using multiple detection methods.
func isMullvadInterface(iface *net.Interface) (bool, error) {
	if iface == nil {
		return false, fmt.Errorf("nil interface provided")
	}

	// Check interface name patterns
	for _, pattern := range mullvadPatterns {
		if strings.Contains(strings.ToLower(iface.Name), pattern) {
			return true, nil
		}
	}

	// Get interface addresses
	addrs, err := iface.Addrs()
	if err != nil {
		return false, fmt.Errorf("failed to get addresses for interface %s: %w", iface.Name, err)
	}

	// Check for Mullvad IP range
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ipNet.IP.To4() != nil && strings.HasPrefix(ipNet.IP.String(), MullvadIPPrefix) {
			return true, nil
		}
	}

	return false, nil
}
