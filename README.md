# netdetect

A Go package for detecting and identifying VPN network interfaces, currently supporting Tailscale, Mullvad, ProtonVPN, and IVPN.

[![Go Report Card](https://goreportcard.com/badge/github.com/eyedeekay/netdetect)](https://goreportcard.com/report/github.com/eyedeekay/netdetect)
[![GoDoc](https://godoc.org/github.com/eyedeekay/netdetect?status.svg)](https://godoc.org/github.com/eyedeekay/netdetect)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- Detection of VPN interfaces by name patterns and IP ranges
- Support for multiple VPN providers:
  - Tailscale (100.x.x.x)
  - Mullvad (10.64.x.x)
  - ProtonVPN (10.2.x.x)
  - IVPN (172.16.x.x)
- Simple API for interface detection
- Zero external dependencies
- Comprehensive test coverage

## Installation

```bash
go get github.com/eyedeekay/netdetect
```

## Usage

```go
package main

import (
    "fmt"
    "github.com/eyedeekay/netdetect"
)

func main() {
    // Find Tailscale interfaces
    tailscaleIfaces, err := netdetect.FindTailscaleInterfaces()
    if err != nil {
        fmt.Printf("Error finding Tailscale interfaces: %v\n", err)
        return
    }
    
    // Find Mullvad interfaces
    mullvadIfaces, err := netdetect.FindMullvadInterfaces()
    if err != nil {
        fmt.Printf("Error finding Mullvad interfaces: %v\n", err)
        return
    }
    
    // Find ProtonVPN interfaces
    protonIfaces, err := netdetect.FindProtonVPNInterfaces()
    if err != nil {
        fmt.Printf("Error finding ProtonVPN interfaces: %v\n", err)
        return
    }
    
    // Find IVPN interfaces
    ivpnIfaces, err := netdetect.FindIVPNInterfaces()
    if err != nil {
        fmt.Printf("Error finding IVPN interfaces: %v\n", err)
        return
    }

    // Print results
    fmt.Printf("Found %d Tailscale interfaces\n", len(tailscaleIfaces))
    fmt.Printf("Found %d Mullvad interfaces\n", len(mullvadIfaces))
    fmt.Printf("Found %d ProtonVPN interfaces\n", len(protonIfaces))
    fmt.Printf("Found %d IVPN interfaces\n", len(ivpnIfaces))
}
```

## API Reference

### Functions

- `FindTailscaleInterfaces() ([]net.Interface, error)`
- `FindMullvadInterfaces() ([]net.Interface, error)`
- `FindProtonVPNInterfaces() ([]net.Interface, error)`
- `FindIVPNInterfaces() ([]net.Interface, error)`

Each function returns a slice of network interfaces identified as belonging to the respective VPN provider, along with any error encountered during detection.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.