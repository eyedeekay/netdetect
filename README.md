# netdetect

A Go package for detecting VPN, mesh, and overlay network interfaces. Currently supports detection for Tailscale, Mullvad, ProtonVPN, IVPN, AirVPN, Yggdrasil, and CJDNS networks.

[![Go Report Card](https://goreportcard.com/badge/github.com/eyedeekay/netdetect)](https://goreportcard.com/report/github.com/eyedeekay/netdetect)
[![GoDoc](https://godoc.org/github.com/eyedeekay/netdetect?status.svg)](https://godoc.org/github.com/eyedeekay/netdetect)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [API Reference](#api-reference)
- [Contributing](#contributing)
- [License](#license)

## Features

- Detection of network interfaces by name patterns and IP ranges
- Support for multiple network types:
  - Commercial VPNs:
    - Mullvad (10.64.x.x)
    - ProtonVPN (10.2.x.x)
    - IVPN (172.16.x.x)
    - AirVPN (10.4.x.x, 10.30.x.x)
  - Overlay Networks:
    - Tailscale (100.x.x.x)
  - Mesh Networks:
    - Yggdrasil (200::/7)
    - CJDNS (fc00::/8)
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
    // Find interfaces for different network types
    tailscaleIfaces, _ := netdetect.FindTailscaleInterfaces()
    mullvadIfaces, _ := netdetect.FindMullvadInterfaces()
    protonIfaces, _ := netdetect.FindProtonVPNInterfaces()
    ivpnIfaces, _ := netdetect.FindIVPNInterfaces()
    airVPNIfaces, _ := netdetect.FindAirVPNInterfaces()
    yggIfaces, _ := netdetect.FindYggdrasilInterfaces()
    cjdnsIfaces, _ := netdetect.FindCJDNSInterfaces()

    // Print results
    fmt.Printf("Found %d Tailscale interfaces\n", len(tailscaleIfaces))
    fmt.Printf("Found %d Mullvad interfaces\n", len(mullvadIfaces))
    fmt.Printf("Found %d ProtonVPN interfaces\n", len(protonIfaces))
    fmt.Printf("Found %d IVPN interfaces\n", len(ivpnIfaces))
    fmt.Printf("Found %d AirVPN interfaces\n", len(airVPNIfaces))
    fmt.Printf("Found %d Yggdrasil interfaces\n", len(yggIfaces))
    fmt.Printf("Found %d CJDNS interfaces\n", len(cjdnsIfaces))
}
```

## API Reference

### Functions

- `FindTailscaleInterfaces() ([]net.Interface, error)`
- `FindMullvadInterfaces() ([]net.Interface, error)`
- `FindProtonVPNInterfaces() ([]net.Interface, error)`
- `FindIVPNInterfaces() ([]net.Interface, error)`
- `FindAirVPNInterfaces() ([]net.Interface, error)`
- `FindYggdrasilInterfaces() ([]net.Interface, error)`
- `FindCJDNSInterfaces() ([]net.Interface, error)`

Each function returns:
- A slice of network interfaces identified as belonging to the respective network
- Any error encountered during detection

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.