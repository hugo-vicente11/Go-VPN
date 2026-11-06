package session

import (
	"sync"
)

const (
	// windowSize is how many counters, ending at the highest one accepted, the
	// replay window remembers. A counter older than that is rejected.
	windowSize = 64
)

// replayWindow tracks which recent counters have been accepted, so each
// counter is accepted at most once. Bit i of bitmap is set if counter
// max - i has been accepted.
//
// The zero value is ready to use and accepts counter 0 first. It is safe for
// concurrent use.
type replayWindow struct {
	mutex  sync.Mutex
	max    uint64
	bitmap uint64
}

// accept marks counter as accepted if it is new. It returns ErrReplay if
// counter was already accepted, is too old for the
// window, or is not below counterLimit. It changes nothing when it returns
// an error.
//
// Calling accept marks counter as seen, so call it only for messages that
// passed authentication.
func (w *replayWindow) accept(counter uint64) error {
	if counter >= counterLimit {
		return ErrReplay
	}

	w.mutex.Lock()
	defer w.mutex.Unlock()
	if counter > w.max {
		offset := counter - w.max
		if offset >= windowSize {
			w.bitmap = 0
		} else {
			w.bitmap = w.bitmap << offset
		}
		w.bitmap = w.bitmap | 1
		w.max = counter
	} else {
		offset := w.max - counter
		if offset >= windowSize {
			return ErrReplay
		}

		if ((1 << offset) & w.bitmap) != 0 {
			return ErrReplay
		}

		w.bitmap = w.bitmap | (1 << offset)
	}
	return nil
}
