package openvpn

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

// --- helpers ---

// newTestClient creates a minimal Client for unit testing (no real connection).
func newTestClient() *Client {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{
		cfg: &Config{
			Remotes: []Remote{{Server: "127.0.0.1", Port: 1194, UDP: true}},
		},
		handshakeStarted: make(chan struct{}, 1),
		errChan:          make(chan error, 10),
		ctx:              ctx,
		cancel:           cancel,
	}
	c.controlConn = NewControlConn(c)
	return c
}

// --- IsAlive / Close tests ---

func TestIsAlive_InitiallyDead(t *testing.T) {
	c := newTestClient()
	defer c.cancel()

	if c.IsAlive() {
		t.Fatal("new client should not be alive before Dial")
	}
}

func TestIsAlive_AfterSetAlive(t *testing.T) {
	c := newTestClient()
	defer c.cancel()

	atomic.StoreInt32(&c.alive, 1)
	if !c.IsAlive() {
		t.Fatal("client should be alive after setting alive=1")
	}
}

func TestClose_SetsDeadAndInvokesCallback(t *testing.T) {
	c := newTestClient()
	atomic.StoreInt32(&c.alive, 1)

	callbackCalled := make(chan struct{}, 1)
	c.SetOnClose(func() {
		callbackCalled <- struct{}{}
	})

	err := c.Close()
	if err != nil {
		t.Fatalf("Close() returned error: %v", err)
	}

	if c.IsAlive() {
		t.Fatal("client should be dead after Close()")
	}

	select {
	case <-callbackCalled:
		// ok
	case <-time.After(1 * time.Second):
		t.Fatal("onClose callback was not invoked")
	}
}

func TestClose_Idempotent(t *testing.T) {
	c := newTestClient()
	atomic.StoreInt32(&c.alive, 1)

	callCount := int32(0)
	c.SetOnClose(func() {
		atomic.AddInt32(&callCount, 1)
	})

	// Close twice
	c.Close()
	c.Close()

	time.Sleep(50 * time.Millisecond)
	if atomic.LoadInt32(&callCount) != 1 {
		t.Fatalf("onClose callback should be called exactly once, got %d", callCount)
	}
}

// --- errorMonitor tests ---

func TestErrorMonitor_ClosesOnError(t *testing.T) {
	c := newTestClient()
	atomic.StoreInt32(&c.alive, 1)

	closeCalled := make(chan struct{}, 1)
	c.SetOnClose(func() {
		closeCalled <- struct{}{}
	})

	go c.errorMonitor()

	// Send a fatal error
	c.errChan <- fmt.Errorf("connection reset")

	select {
	case <-closeCalled:
		// errorMonitor detected the error and closed
	case <-time.After(2 * time.Second):
		t.Fatal("errorMonitor did not close the client on error")
	}

	if c.IsAlive() {
		t.Fatal("client should be dead after errorMonitor handles error")
	}
}

func TestErrorMonitor_StopsOnContextCancel(t *testing.T) {
	c := newTestClient()
	atomic.StoreInt32(&c.alive, 1)

	done := make(chan struct{})
	go func() {
		c.errorMonitor()
		close(done)
	}()

	c.cancel()

	select {
	case <-done:
		// errorMonitor exited
	case <-time.After(2 * time.Second):
		t.Fatal("errorMonitor did not exit on context cancellation")
	}
}

// --- pingLoop tests ---

func TestPingLoop_TimeoutDetection(t *testing.T) {
	c := newTestClient()
	atomic.StoreInt32(&c.alive, 1)

	// pingLoop calls updateActivity() on start, so we override lastActivity
	// AFTER it starts but BEFORE the first 10s tick.
	done := make(chan struct{})
	go func() {
		c.pingLoop()
		close(done)
	}()

	// Wait a moment for pingLoop to call updateActivity(), then force stale
	time.Sleep(100 * time.Millisecond)
	atomic.StoreInt64(&c.lastActivity, time.Now().Unix()-20) // 20s stale, exceeds 15s threshold

	// First ticker fires at ~10s, at which point it will detect staleness
	select {
	case err := <-c.errChan:
		if err == nil || err.Error() != "ping timeout" {
			t.Fatalf("expected ping timeout error, got: %v", err)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("pingLoop did not detect timeout within expected time")
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pingLoop did not exit after timeout")
	}
}

func TestPingLoop_StopsOnContextCancel(t *testing.T) {
	c := newTestClient()
	c.updateActivity()

	done := make(chan struct{})
	go func() {
		c.pingLoop()
		close(done)
	}()

	// Cancel context
	c.cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pingLoop did not exit on context cancellation")
	}
}

// --- Dial tests ---

func TestDial_NoRemotes(t *testing.T) {
	c := newTestClient()
	c.cfg.Remotes = nil
	defer c.cancel()

	err := c.Dial(context.Background())
	if err == nil {
		t.Fatal("expected error for no remotes")
	}
	if err.Error() != "no remotes configured" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDial_SingleRemote_UnreachableServer(t *testing.T) {
	c := newTestClient()
	c.cfg.Remotes = []Remote{{Server: "192.0.2.1", Port: 9999, UDP: false}} // TEST-NET, unreachable
	defer c.cancel()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := c.Dial(ctx)
	if err == nil {
		t.Fatal("expected error connecting to unreachable server")
	}
}

func TestDial_MultipleRemotes_AllUnreachable(t *testing.T) {
	c := newTestClient()
	c.cfg.Remotes = []Remote{
		{Server: "192.0.2.1", Port: 9999, UDP: false},
		{Server: "192.0.2.2", Port: 9999, UDP: false},
		{Server: "192.0.2.3", Port: 9999, UDP: false},
	}
	defer c.cancel()

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	start := time.Now()
	err := c.Dial(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error connecting to all unreachable servers")
	}

	// With parallel connection, all 3 should fail roughly at the same time
	// (within the context timeout), not 3x sequential
	if elapsed > 10*time.Second {
		t.Fatalf("parallel dial took too long: %v (should be < 10s for parallel)", elapsed)
	}
	t.Logf("parallel dial to 3 unreachable remotes took %v", elapsed)
}

// --- SetOnClose tests ---

func TestSetOnClose_NilSafe(t *testing.T) {
	c := newTestClient()
	atomic.StoreInt32(&c.alive, 1)
	// No onClose set - should not panic
	err := c.Close()
	if err != nil {
		t.Fatalf("Close() with nil onClose should not error: %v", err)
	}
}

// --- updateActivity tests ---

func TestUpdateActivity(t *testing.T) {
	c := newTestClient()
	defer c.cancel()

	before := time.Now().Unix()
	c.updateActivity()
	after := time.Now().Unix()

	activity := atomic.LoadInt64(&c.lastActivity)
	if activity < before || activity > after {
		t.Fatalf("lastActivity %d not in range [%d, %d]", activity, before, after)
	}
}
