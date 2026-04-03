package crypto

import (
	"sync"
)

// ReplayWindow implements a sliding window to detect replayed or stale packets.
// It is thread-safe and designed to be used in data channel decryption.
type ReplayWindow struct {
	windowSize uint32
	maxSeen    uint32
	bitmask    uint64
	mutex      sync.Mutex
}

// NewReplayWindow creates a new ReplayWindow with the given size.
// The size should ideally be a multiple of 64.
func NewReplayWindow(size uint32) *ReplayWindow {
	if size == 0 {
		size = 64
	}
	if size > 64 {
		size = 64 // Max 64 for uint64 bitmask, can be extended if larger window needed
	}
	return &ReplayWindow{
		windowSize: size,
		maxSeen:    0,
		bitmask:    0,
	}
}

// Check returns true if the packetID is valid (not replayed and within window).
// It does NOT update the window.
func (rw *ReplayWindow) Check(packetID uint32) bool {
	rw.mutex.Lock()
	defer rw.mutex.Unlock()

	// Packet ID must be > 0
	if packetID == 0 {
		return false
	}

	// New highest packet ID
	if packetID > rw.maxSeen {
		return true
	}

	// Packet is too old, outside the sliding window
	if rw.maxSeen-packetID >= rw.windowSize {
		return false
	}

	// Check if we've already seen this packet
	shift := rw.maxSeen - packetID
	return (rw.bitmask & (1 << shift)) == 0
}

// Update marks the packetID as seen and slides the window if necessary.
func (rw *ReplayWindow) Update(packetID uint32) {
	rw.mutex.Lock()
	defer rw.mutex.Unlock()

	if packetID == 0 {
		return
	}

	if packetID > rw.maxSeen {
		diff := packetID - rw.maxSeen
		if diff >= rw.windowSize {
			// Window completely shifted
			rw.bitmask = 1
		} else {
			// Shift bitmask
			rw.bitmask <<= diff
			rw.bitmask |= 1
		}
		rw.maxSeen = packetID
	} else {
		diff := rw.maxSeen - packetID
		if diff < rw.windowSize {
			rw.bitmask |= (1 << diff)
		}
	}
}