package main

import (
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hugo-vicente11/go-vpn/internal/session"
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

// testKeyFileContent is a key file as wg genkey writes it, with a trailing
// newline. It decodes to the bytes 0 to 31.
const testKeyFileContent = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n"

func TestLoadKey(t *testing.T) {
	var want session.Key
	for i := range want {
		want[i] = byte(i)
	}

	tests := []struct {
		name    string
		content string // file content; empty means the file is not created
		mode    os.FileMode
		wantErr string // substring the error must contain; empty means success
	}{
		{"valid", testKeyFileContent, 0o600, ""},
		{"group readable", testKeyFileContent, 0o640, "chmod 600"},
		{"world readable", testKeyFileContent, 0o644, "chmod 600"},
		{"missing", "", 0, "no such file"},
		{"garbage", "not a key", 0o600, "not valid base64"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "govpn.key")
			if tc.content != "" {
				if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
					t.Fatal(err)
				}
				// WriteFile's mode is reduced by the umask, so set it explicitly.
				if err := os.Chmod(path, tc.mode); err != nil {
					t.Fatal(err)
				}
			}

			got, err := loadKey(path)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("loadKey: %v", err)
				}
				if got != want {
					t.Errorf("loadKey = %x, want %x", got, want)
				}
				return
			}

			if err == nil {
				t.Fatalf("loadKey returned nil error, want one containing %q", tc.wantErr)
			}
			if msg := err.Error(); !strings.Contains(msg, tc.wantErr) {
				t.Errorf("loadKey error = %q, want it to contain %q", msg, tc.wantErr)
			}
			// Every error must name the file, so the user knows which one to fix.
			if msg := err.Error(); !strings.Contains(msg, path) {
				t.Errorf("loadKey error = %q, want it to name %s", msg, path)
			}
		})
	}
}

// TestLoadKeyMissingIsNotExist checks that a missing file can still be
// recognized with errors.Is after loadKey wraps the error.
func TestLoadKeyMissingIsNotExist(t *testing.T) {
	_, err := loadKey(filepath.Join(t.TempDir(), "missing.key"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("loadKey error = %v, want it to wrap %v", err, fs.ErrNotExist)
	}
}
