// Package netdetect provides utilities for detecting and identifying specific
// network interfaces on a system.
package netdetect

import (
	"fmt"
	"net"
	"strings"
)

// AirVPNIPPrefix defines the known IPv4 prefix for AirVPN addresses
// AirVPN typically uses 10.4.0.0/16 and 10.30.0.0/16 for its tunnel interfaces
var airVPNIPPrefixes = []string{
	"10.4.",
	"10.30.",
}

// Common AirVPN interface name patterns
var airVPNPatterns = []string{
	"air",
	"airvpn",
	"tun-air",
	"air-",
}

// FindAirVPNInterfaces returns a slice of network interfaces that are
// identified as AirVPN tunnel interfaces. It uses multiple detection
// methods including interface naming patterns and IP address assignments.
//
// Returns:
//   - []net.Interface: Slice of identified AirVPN interfaces
//   - error: Any error encountered during interface detection
//
// The function may return an empty slice if no AirVPN interfaces are found.
func FindAirVPNInterfaces() ([]net.Interface, error) {
	// Get all network interfaces
	allInterfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to list network interfaces: %w", err)
	}

	var airVPNInterfaces []net.Interface

	// Iterate through interfaces to identify AirVPN ones
	for _, iface := range allInterfaces {
		isAirVPN, err := isAirVPNInterface(&iface)
		if err != nil {
			// Log the error but continue checking other interfaces
			continue
		}
		if isAirVPN {
			airVPNInterfaces = append(airVPNInterfaces, iface)
		}
	}

	return airVPNInterfaces, nil
}

// isAirVPNInterface checks if the given interface is an AirVPN interface
// using multiple detection methods.
func isAirVPNInterface(iface *net.Interface) (bool, error) {
	if iface == nil {
		return false, fmt.Errorf("nil interface provided")
	}

	// Check interface name patterns
	for _, pattern := range airVPNPatterns {
		if strings.Contains(strings.ToLower(iface.Name), pattern) {
			return true, nil
		}
	}

	// Get interface addresses
	addrs, err := iface.Addrs()
	if err != nil {
		return false, fmt.Errorf("failed to get addresses for interface %s: %w", iface.Name, err)
	}

	// Check for AirVPN IP ranges
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ipNet.IP.To4() != nil {
			for _, prefix := range airVPNIPPrefixes {
				if strings.HasPrefix(ipNet.IP.String(), prefix) {
					return true, nil
				}
			}
		}
	}

	return false, nil
}
