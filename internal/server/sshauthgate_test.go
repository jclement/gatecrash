package server

import (
	"testing"
	"time"
)

func TestSSHAuthGate_PerIPRateLimit(t *testing.T) {
	s := &Server{
		sshAuthLimiter:        newIPRateLimiter(3, time.Minute),
		bcryptSem:             make(chan struct{}, 8),
		sshAuthAcquireTimeout: time.Second,
	}
	for i := 0; i < 3; i++ {
		ok, release := s.sshAuthGate("1.2.3.4")
		if !ok {
			t.Fatalf("attempt %d should be allowed", i+1)
		}
		release() // free the bcrypt slot each time
	}
	if ok, _ := s.sshAuthGate("1.2.3.4"); ok {
		t.Fatal("4th attempt from same IP should be rate limited")
	}
	// A different IP is unaffected.
	if ok, release := s.sshAuthGate("5.6.7.8"); !ok {
		t.Fatal("different IP should be allowed")
	} else {
		release()
	}
}

func TestSSHAuthGate_BoundsConcurrentBcrypt(t *testing.T) {
	s := &Server{
		sshAuthLimiter:        newIPRateLimiter(1000, time.Minute),
		bcryptSem:             make(chan struct{}, 1),
		sshAuthAcquireTimeout: 50 * time.Millisecond,
	}
	ok1, release1 := s.sshAuthGate("9.9.9.9")
	if !ok1 {
		t.Fatal("first attempt should acquire the single slot")
	}
	// Second attempt (different IP, slot held) must time out and be shed.
	start := time.Now()
	ok2, _ := s.sshAuthGate("8.8.8.8")
	if ok2 {
		t.Fatal("second concurrent attempt should be shed while slot is held")
	}
	if time.Since(start) < 40*time.Millisecond {
		t.Fatal("expected it to wait for the acquire timeout before shedding")
	}
	release1()
	if ok3, release3 := s.sshAuthGate("8.8.8.8"); !ok3 {
		t.Fatal("attempt should succeed after the slot is released")
	} else {
		release3()
	}
}
