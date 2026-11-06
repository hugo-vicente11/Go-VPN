package session

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

// step is one call to accept and whether it should succeed.
type step struct {
	counter uint64
	ok      bool
}

// runSteps calls w.accept for each step in order, checking that it succeeds
// or returns ErrReplay as the step expects.
func runSteps(t *testing.T, w *replayWindow, steps []step) {
	t.Helper()
	for i, s := range steps {
		err := w.accept(s.counter)
		switch {
		case s.ok && err != nil:
			t.Errorf("step %d: accept(%d) = %v, want nil", i, s.counter, err)
		case !s.ok && !errors.Is(err, ErrReplay):
			t.Errorf("step %d: accept(%d) = %v, want %v", i, s.counter, err, ErrReplay)
		}
	}
}

func TestReplayWindowAccept(t *testing.T) {
	// far is a counter high enough that far - windowSize does not wrap around.
	const far = 1000

	tests := []struct {
		name  string
		steps []step
	}{
		{
			name: "gaps and reordering",
			steps: []step{
				{10, true}, {11, true}, {13, true}, {14, true}, {16, true},
				{12, true},
				{12, false},
				{5, true},
				{5, false},
			},
		},
		{
			name:  "same counter twice",
			steps: []step{{10, true}, {10, false}},
		},
		{
			name:  "out of order, not seen",
			steps: []step{{10, true}, {12, true}, {11, true}},
		},
		{
			name:  "out of order, already seen",
			steps: []step{{10, true}, {12, true}, {11, true}, {11, false}, {10, false}},
		},
		{
			name: "oldest counter inside the window",
			steps: []step{
				{far, true},
				{far - (windowSize - 1), true},
				{far - (windowSize - 1), false},
			},
		},
		{
			name: "newest counter outside the window, never seen",
			steps: []step{
				{far, true},
				{far - windowSize, false},
			},
		},
		{
			name: "small jump keeps older counters",
			steps: []step{
				{10, true},
				{20, true},
				{10, false},
				{11, true},
			},
		},
		{
			// 10 slides to the oldest bit of the window and must still be remembered.
			name: "jump to the edge of the window",
			steps: []step{
				{10, true},
				{10 + windowSize - 1, true},
				{10, false},
				{11, true},
			},
		},
		{
			name: "jump of a whole window forgets older counters",
			steps: []step{
				{10, true},
				{10 + windowSize, true},
				{10, false},
				{11, true},
			},
		},
		{
			name: "counter limit",
			steps: []step{
				{counterLimit, false},
				{counterLimit + 1, false},
				{^uint64(0), false},
				{counterLimit - 1, true},
				{counterLimit - 1, false},
			},
		},
		{
			// If a rejected counter moved the window, the counters after it
			// would be judged against the wrong highest counter.
			name: "rejected counters change nothing",
			steps: []step{
				{far, true},
				{far - windowSize, false},
				{counterLimit, false},
				{far, false},
				{far - (windowSize - 1), true},
				{far + 1, true},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var w replayWindow
			runSteps(t, &w, tc.steps)
		})
	}
}

// TestReplayWindowConcurrent checks that when many goroutines accept the same
// counter at once, exactly one succeeds. Run it with -race.
func TestReplayWindowConcurrent(t *testing.T) {
	const goroutines = 100

	var w replayWindow
	var accepted atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})

	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if w.accept(7) == nil {
				accepted.Add(1)
			}
		}()
	}

	// Release all goroutines together, so their calls overlap as much as possible.
	close(start)
	wg.Wait()

	if got := accepted.Load(); got != 1 {
		t.Errorf("accept(7) succeeded %d times, want 1", got)
	}
}

// TestReplayWindowZeroValue checks that a new window accepts counter 0 once.
// A new window starts with max = 0, the same as a window that has accepted 0,
// so only the empty bitmap tells the two apart.
func TestReplayWindowZeroValue(t *testing.T) {
	var w replayWindow
	runSteps(t, &w, []step{
		{0, true},
		{0, false},
		{1, true},
	})
}
