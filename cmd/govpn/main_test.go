package main

import (
	"net/netip"
	"strings"
	"testing"
)

func TestValidateTunnelAddr(t *testing.T) {
	tests := []struct {
		name    string
		input   netip.Prefix
		wantErr bool
	}{
		{"host address", netip.MustParsePrefix("10.0.0.1/24"), false},
		{"length 30 host address", netip.MustParsePrefix("10.0.0.1/30"), false},
		{"length 31 point-to-point", netip.MustParsePrefix("10.0.0.0/31"), false},
		{"empty", netip.Prefix{}, true},
		{"IPv6", netip.MustParsePrefix("fd00::1/64"), true},
		{"length 32", netip.MustParsePrefix("10.0.0.1/32"), true},
		{"network address", netip.MustParsePrefix("10.0.0.0/24"), true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTunnelAddr(tc.input)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("validateTunnelAddr(%v) error = %v, wantErr %v", tc.input, err, tc.wantErr)
			}
		})
	}
}

// TestValidateTunnelAddrSuggestsHost checks that rejecting a network address
// suggests the first host address with the same prefix length, ready to copy.
func TestValidateTunnelAddrSuggestsHost(t *testing.T) {
	err := validateTunnelAddr(netip.MustParsePrefix("10.0.0.0/24"))
	if err == nil {
		t.Fatal("validateTunnelAddr(10.0.0.0/24) returned nil, want error")
	}

	const want = "such as 10.0.0.1/24"
	if msg := err.Error(); !strings.HasSuffix(msg, want) {
		t.Errorf("error = %q, want it to end with %q", msg, want)
	}
}
