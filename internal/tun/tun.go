package tun

import (
	"bytes"
	"fmt"
	"net/netip"
	"os/exec"

	"github.com/songgao/water"
)

// Device wraps a TUN interface
type Device struct {
	iface *water.Interface
}

// New creates a new TUN device
func New() (*Device, error) {
	config := water.Config{
		DeviceType: water.TUN,
	}

	iface, err := water.New(config)
	if err != nil {
		return nil, err
	}

	return &Device{iface: iface}, nil
}

// Read reads a raw packet from TUN device into p
func (d *Device) Read(p []byte) (int, error) {
	return d.iface.Read(p)
}

// Write writes a raw packet from p to the TUN device
func (d *Device) Write(p []byte) (int, error) {
	return d.iface.Write(p)
}

// Name returns the OS-assigned interface name (e.g. "tun0" or "utun3")
func (d *Device) Name() string {
	return d.iface.Name()
}

// Configure assigns addr to the device and brings it up.
func (d *Device) Configure(addr netip.Prefix) error {
	cmd := exec.Command("ip", "addr", "add", addr.String(), "dev", d.Name())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("adding address %s to %s: %s: %w", addr.String(), d.Name(), bytes.TrimSpace(out), err)
	}

	cmd = exec.Command("ip", "link", "set", "dev", d.Name(), "up")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("bringing %s up: %s: %w", d.Name(), bytes.TrimSpace(out), err)
	}

	return nil
}

// Close closes the TUN device
func (d *Device) Close() error {
	return d.iface.Close()
}
