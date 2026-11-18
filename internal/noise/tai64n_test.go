package noise

import (
	"bytes"
	"testing"
	"time"
)

func TestTAI64N(t *testing.T) {
	tests := []struct {
		name string
		time time.Time
		want string
	}{
		{"Unix epoch", time.Unix(0, 0), "400000000000000a00000000"},
		{"seconds and nanoseconds", time.Unix(1, 2), "400000000000000b00000002"},
		{"every byte different", time.Unix(0x0102030405, 0x0708090a), "400000010203040f0708090a"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tai64n(tc.time)
			checkHex(t, "tai64n", got[:], tc.want)
		})
	}
}

// TestTAI64NOrder checks that a later time gives a greater timestamp under
// bytes.Compare, which is how the responder rejects replayed messages.
func TestTAI64NOrder(t *testing.T) {
	base := time.Unix(1000, 500)

	tests := []struct {
		name  string
		later time.Time
	}{
		{"one nanosecond later", base.Add(time.Nanosecond)},
		{"one second later", base.Add(time.Second)},
		{"next second, fewer nanoseconds", time.Unix(1001, 0)},
		{"256 seconds later", base.Add(256 * time.Second)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			earlier, later := tai64n(base), tai64n(tc.later)
			if bytes.Compare(later[:], earlier[:]) <= 0 {
				t.Errorf("tai64n(%v) = %x is not greater than tai64n(%v) = %x", tc.later, later, base, earlier)
			}
		})
	}
}
