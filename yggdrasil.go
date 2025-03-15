package netdetect

import (
	"fmt"
	"net"
	"strings"
)

// YggdrasilIPPrefix defines the known IPv6 prefix for Yggdrasil addresses
// Yggdrasil uses 200::/7 for its network addresses
const YggdrasilIPPrefix = "200:"

// Common Yggdrasil interface name patterns
var yggdrasilPatterns = []string{
	"ygg",
	"tun-ygg",
	"yggdrasil",
	"ygg0",
}

// FindYggdrasilInterfaces returns a slice of network interfaces that are
// identified as Yggdrasil tunnel interfaces. It uses multiple detection
// methods including interface naming patterns and IPv6 address assignments.
//
// Returns:
//   - []net.Interface: Slice of identified Yggdrasil interfaces
//   - error: Any error encountered during interface detection
//
// The function may return an empty slice if no Yggdrasil interfaces are found.
func FindYggdrasilInterfaces() ([]net.Interface, error) {
	// Get all network interfaces
	allInterfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to list network interfaces: %w", err)
	}

	var yggdrasilInterfaces []net.Interface

	// Iterate through interfaces to identify Yggdrasil ones
	for _, iface := range allInterfaces {
		isYggdrasil, err := isYggdrasilInterface(&iface)
		if err != nil {
			// Log the error but continue checking other interfaces
			continue
		}
		if isYggdrasil {
			yggdrasilInterfaces = append(yggdrasilInterfaces, iface)
		}
	}

	return yggdrasilInterfaces, nil
}

// isYggdrasilInterface checks if the given interface is a Yggdrasil interface
// using multiple detection methods.
func isYggdrasilInterface(iface *net.Interface) (bool, error) {
	if iface == nil {
		return false, fmt.Errorf("nil interface provided")
	}

	// Check interface name patterns
	for _, pattern := range yggdrasilPatterns {
		if strings.Contains(strings.ToLower(iface.Name), pattern) {
			return true, nil
		}
	}

	// Get interface addresses
	addrs, err := iface.Addrs()
	if err != nil {
		return false, fmt.Errorf("failed to get addresses for interface %s: %w", iface.Name, err)
	}

	// Check for Yggdrasil IPv6 range
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		// Yggdrasil uses IPv6, so we specifically check for IPv6 addresses
		if ipNet.IP.To4() == nil && strings.HasPrefix(ipNet.IP.String(), YggdrasilIPPrefix) {
			return true, nil
		}
	}

	return false, nil
}
