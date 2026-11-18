package noise

import (
	"encoding/binary"
	"time"
)

// tai64Epoch is 2^62 + 10: TAI64 counts from 2^62, and TAI was 10 seconds
// ahead of UTC in 1970.
const tai64Epoch = 0x400000000000000a

// tai64n returns t as a 12-byte TAI64N timestamp: the seconds plus
// tai64Epoch, then the nanoseconds, both big-endian. The initiator encrypts
// one in the first handshake message, and the responder rejects any that is
// not greater than the last one it accepted, so an old message cannot be
// replayed.
//
// Big-endian makes bytes.Compare order the timestamps the same way as the
// times they hold.
func tai64n(t time.Time) [12]byte {
	var res [12]byte
	binary.BigEndian.PutUint64(res[:8], tai64Epoch+uint64(t.Unix()))
	binary.BigEndian.PutUint32(res[8:], uint32(t.Nanosecond()))

	return res
}
