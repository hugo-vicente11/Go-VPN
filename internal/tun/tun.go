package tun

import (
	"fmt"

	"github.com/songgao/water"
)

// Device wraps a TUN interface
type Device struct {
	iface *water.Interface
}

// New creates and brings up a new TUN device
func New() (*Device, error) {
	config := water.Config{
		DeviceType: water.TUN,
	}

	iface, err := water.New(config)
	if err != nil {
		return nil, fmt.Errorf("creating tun device: %w", err)
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

// Close closes the TUN device
func (d *Device) Close() error {
	return d.iface.Close()
}
