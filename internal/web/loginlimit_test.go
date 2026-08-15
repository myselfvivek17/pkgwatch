package web

import (
	"testing"
	"time"
)

// Hashing is serialised, so concurrency cannot multiply the memory cost.
//
// This is the property that matters most: argon2id is 64 MiB per call by
// design, so an unauthenticated endpoint that hashes on demand is a memory
// amplifier long before it is a guessing target.
func TestOnlyOnePasswordIsHashedAtATime(t *testing.T) {
	var l loginLimiter
	now := time.Now()

	var inFlight, peak int
	done := make(chan struct{})

	for i := 0; i < 8; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			l.attempt(now, func() bool {
				// Inside the lock, so this bookkeeping needs none of its own.
				inFlight++
				if inFlight > peak {
					peak = inFlight
				}
				time.Sleep(time.Millisecond)
				inFlight--
				return false
			})
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}

	if peak > 1 {
		t.Errorf("%d hashes ran at once; 8 concurrent sign-ins would be %d MiB", peak, peak*64)
	}
}

// Failures get progressively slower, and a correct password clears it.
func TestFailuresBackOffAndSuccessResets(t *testing.T) {
	var l loginLimiter
	now := time.Now()

	if wait := l.wait(now); wait != 0 {
		t.Fatalf("a first attempt had to wait %s", wait)
	}
	if l.attempt(now, func() bool { return false }) {
		t.Fatal("a wrong password was accepted")
	}

	first := l.wait(now)
	if first <= 0 {
		t.Fatal("no backoff after a failure")
	}

	// A second failure, once the first window has passed, costs more.
	later := now.Add(first + time.Millisecond)
	l.attempt(later, func() bool { return false })
	if second := l.wait(later); second <= first {
		t.Errorf("backoff did not grow: %s then %s", first, second)
	}

	// The right password clears the whole thing, so the owner is never left
	// waiting for an attacker's failures.
	past := later.Add(loginBackoffMax)
	if !l.attempt(past, func() bool { return true }) {
		t.Fatal("the correct password was refused")
	}
	if wait := l.wait(past); wait != 0 {
		t.Errorf("still throttled after a successful sign-in: %s", wait)
	}
}

// A refused attempt must not reach the hash at all — otherwise the throttle
// slows the answer without saving the memory it exists to save.
func TestAThrottledAttemptNeverHashes(t *testing.T) {
	var l loginLimiter
	now := time.Now()

	l.attempt(now, func() bool { return false }) // arms the backoff

	hashed := false
	if l.attempt(now, func() bool { hashed = true; return true }) {
		t.Error("an attempt inside the backoff window was accepted")
	}
	if hashed {
		t.Error("the password was hashed during the backoff window")
	}
}

// Backoff is bounded. An unbounded doubling would eventually lock the owner out
// for hours, turning a guessing attempt into a denial of service.
func TestBackoffIsCapped(t *testing.T) {
	if got := backoffFor(50); got != loginBackoffMax {
		t.Errorf("backoff after 50 failures = %s, want the %s cap", got, loginBackoffMax)
	}
	if got := backoffFor(1); got != loginBackoffStart {
		t.Errorf("first failure = %s, want %s", got, loginBackoffStart)
	}
}
