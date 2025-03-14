package netdetect

import (
	"net"
	"testing"
)

func TestFindTailscaleInterfaces(t *testing.T) {
	interfaces, err := FindTailscaleInterfaces()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Log found interfaces for debugging
	t.Logf("Found %d Tailscale interfaces", len(interfaces))
	for _, iface := range interfaces {
		t.Logf("Interface: %s", iface.Name)
	}

	// Note: We can't make specific assertions about the number of interfaces
	// as it depends on the system configuration
}

func TestIsTailscaleInterface(t *testing.T) {
	tests := []struct {
		name      string
		ifaceName string
		want      bool
	}{
		{
			name:      "Typical Tailscale interface",
			ifaceName: "tailscale0",
			want:      true,
		},
		{
			name:      "Alternative Tailscale naming",
			ifaceName: "ts0",
			want:      true,
		},
		{
			name:      "Non-Tailscale interface",
			ifaceName: "eth0",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock interface for testing
			iface := &net.Interface{
				Name: tt.ifaceName,
			}

			got, err := isTailscaleInterface(iface)
			if err != nil {
				t.Errorf("isTailscaleInterface() error = %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("isTailscaleInterface() = %v, want %v", got, tt.want)
			}
		})
	}
}
