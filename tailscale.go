// Package netdetect provides utilities for detecting and identifying specific
// network interfaces on a system.
package netdetect

import (
	"fmt"
	"net"
	"strings"
)

// TailscaleIPPrefix defines the known IPv4 prefix for Tailscale addresses
const TailscaleIPPrefix = "100."

// Common Tailscale interface name patterns
var tailscalePatterns = []string{
	"tailscale",
	"ts",
	"wg-ts", // Some systems use wg-ts prefix
}

// FindTailscaleInterfaces returns a slice of network interfaces that are
// identified as Tailscale tunnel interfaces. It uses multiple detection
// methods including interface naming patterns and IP address assignments.
//
// Returns:
//   - []net.Interface: Slice of identified Tailscale interfaces
//   - error: Any error encountered during interface detection
//
// The function may return an empty slice if no Tailscale interfaces are found.
func FindTailscaleInterfaces() ([]net.Interface, error) {
	// Get all network interfaces
	allInterfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to list network interfaces: %w", err)
	}

	var tailscaleInterfaces []net.Interface

	// Iterate through interfaces to identify Tailscale ones
	for _, iface := range allInterfaces {
		isTailscale, err := isTailscaleInterface(&iface)
		if err != nil {
			// Log the error but continue checking other interfaces
			continue
		}
		if isTailscale {
			tailscaleInterfaces = append(tailscaleInterfaces, iface)
		}
	}

	return tailscaleInterfaces, nil
}

// isTailscaleInterface checks if the given interface is a Tailscale interface
// using multiple detection methods.
func isTailscaleInterface(iface *net.Interface) (bool, error) {
	if iface == nil {
		return false, fmt.Errorf("nil interface provided")
	}

	// Check interface name patterns
	for _, pattern := range tailscalePatterns {
		if strings.Contains(strings.ToLower(iface.Name), pattern) {
			return true, nil
		}
	}

	// Get interface addresses
	addrs, err := iface.Addrs()
	if err != nil {
		return false, fmt.Errorf("failed to get addresses for interface %s: %w", iface.Name, err)
	}

	// Check for Tailscale IP range
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ipNet.IP.To4() != nil && strings.HasPrefix(ipNet.IP.String(), TailscaleIPPrefix) {
			return true, nil
		}
	}

	return false, nil
}
