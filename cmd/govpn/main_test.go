package main

import (
	"bytes"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hugo-vicente11/go-vpn/internal/identity"
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

// Alice's key pair from RFC 7748, section 6.1, in base64.
const (
	alicePrivate = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo="
	alicePublic  = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo="
)

// errWrite is the error failingWriter returns.
var errWrite = errors.New("write failed")

// failingWriter is an io.Writer whose writes always fail, like stdout
// redirected to a full disk.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errWrite }

// runGenkey calls genkey and returns what it wrote, failing the test on error.
func runGenkey(t *testing.T) string {
	t.Helper()
	var out bytes.Buffer
	if err := genkey(&out); err != nil {
		t.Fatalf("genkey: %v", err)
	}
	return out.String()
}

func TestGenkey(t *testing.T) {
	out := runGenkey(t)

	key, ok := strings.CutSuffix(out, "\n")
	if !ok {
		t.Fatalf("genkey wrote %q, want it to end with a newline", out)
	}
	if strings.ContainsAny(key, " \t\n") {
		t.Errorf("genkey wrote %q, want only the key and one newline", out)
	}
	if _, err := identity.ParsePrivateKey(key); err != nil {
		t.Errorf("ParsePrivateKey(genkey output): %v", err)
	}
}

func TestGenkeyIsRandom(t *testing.T) {
	if a, b := runGenkey(t), runGenkey(t); a == b {
		t.Errorf("genkey wrote %q twice", a)
	}
}

func TestPubkey(t *testing.T) {
	for _, input := range []string{alicePrivate, alicePrivate + "\n"} {
		var out bytes.Buffer
		if err := pubkey(strings.NewReader(input), &out); err != nil {
			t.Fatalf("pubkey(%q): %v", input, err)
		}
		if got, want := out.String(), alicePublic+"\n"; got != want {
			t.Errorf("pubkey(%q) wrote %q, want %q", input, got, want)
		}
	}
}

// TestPubkeyGenkey checks that pubkey reads what genkey writes, as in
// govpn genkey | govpn pubkey, and gets the same key as identity.
func TestPubkeyGenkey(t *testing.T) {
	private := runGenkey(t)

	var out bytes.Buffer
	if err := pubkey(strings.NewReader(private), &out); err != nil {
		t.Fatalf("pubkey(genkey output): %v", err)
	}

	key, err := identity.ParsePrivateKey(private)
	if err != nil {
		t.Fatalf("ParsePrivateKey(genkey output): %v", err)
	}
	if got, want := out.String(), key.PublicKey().String()+"\n"; got != want {
		t.Errorf("pubkey wrote %q, want %q", got, want)
	}
}

func TestPubkeyRejectsEmptyInput(t *testing.T) {
	for _, input := range []string{"", "\n", "  \t\n"} {
		var out bytes.Buffer
		if err := pubkey(strings.NewReader(input), &out); !errors.Is(err, errNoPrivateKey) {
			t.Errorf("pubkey(%q) error = %v, want %v", input, err, errNoPrivateKey)
		}
		if out.Len() != 0 {
			t.Errorf("pubkey(%q) wrote %q, want nothing", input, out.String())
		}
	}
}

func TestPubkeyRejectsInvalidKey(t *testing.T) {
	for _, input := range []string{"not base64!", "AAAA", alicePublic + "AAAA"} {
		var out bytes.Buffer
		err := pubkey(strings.NewReader(input), &out)
		if err == nil {
			t.Errorf("pubkey(%q) returned nil error, want one", input)
			continue
		}
		if errors.Is(err, errNoPrivateKey) {
			t.Errorf("pubkey(%q) error = %v, want an invalid key error, not %v", input, err, errNoPrivateKey)
		}
		if out.Len() != 0 {
			t.Errorf("pubkey(%q) wrote %q, want nothing", input, out.String())
		}
	}
}

// TestWriteErrors checks that genkey and pubkey report a failed write, so a
// user does not end up with an empty key file and no error.
func TestWriteErrors(t *testing.T) {
	tests := []struct {
		name string
		run  func() error
	}{
		{"genkey", func() error { return genkey(failingWriter{}) }},
		{"pubkey", func() error { return pubkey(strings.NewReader(alicePrivate), failingWriter{}) }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(); !errors.Is(err, errWrite) {
				t.Errorf("error = %v, want it to wrap %v", err, errWrite)
			}
		})
	}
}
