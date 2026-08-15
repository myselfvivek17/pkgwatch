package web

import (
	"sync"
	"time"
)

// Backoff bounds for failed sign-ins.
const (
	loginBackoffStart = 500 * time.Millisecond
	loginBackoffMax   = 15 * time.Second
)

// loginLimiter bounds what an unauthenticated caller can spend of the hub's
// memory and time.
//
// Verifying a password costs 64 MiB, by design — that is what makes argon2id
// worth using. It also means an unauthenticated endpoint that hashes on demand
// is a memory amplifier: a few dozen concurrent requests to /login is over a
// gigabyte, and nothing about that requires knowing the password.
//
// This codebase already reasons this way elsewhere. The device API checks a
// request's signature and the device's status *before* the token, so the hub
// never pays argon2 for a credential it has already decided to reject. The
// dashboard login never inherited that, and this is it.
//
// Two separate controls, because they stop different things:
//
//   - The mutex serialises hashing, so concurrency cannot multiply the memory
//     cost. Peak stays at one hash regardless of how many callers arrive.
//   - The backoff makes repeated failures progressively slower, so guessing is
//     bounded by wall-clock time rather than by how fast the attacker can send.
//
// Deliberately not a lockout. A threshold that disables sign-in would let
// anyone who can reach the port lock the owner out of their own dashboard —
// turning a guessing attempt into a denial of service, which is a worse trade
// than a slow login. Refused attempts are cheap: they are rejected before any
// hashing happens.
type loginLimiter struct {
	mu       sync.Mutex
	failures int
	notUntil time.Time
}

// wait reports how long the caller must wait before another attempt is
// accepted. Zero means go ahead.
func (l *loginLimiter) wait(now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Before(l.notUntil) {
		return l.notUntil.Sub(now)
	}
	return 0
}

// attempt runs verify with hashing serialised, and records the outcome.
func (l *loginLimiter) attempt(now time.Time, verify func() bool) bool {
	// Held across verify on purpose: this is the serialisation, not just a
	// guard around the counters.
	l.mu.Lock()
	defer l.mu.Unlock()

	// Re-checked inside the lock. Without this, every request that passed the
	// wait() check while queued would still get its hash computed.
	if now.Before(l.notUntil) {
		return false
	}

	if verify() {
		l.failures = 0
		l.notUntil = time.Time{}
		return true
	}

	l.failures++
	l.notUntil = now.Add(backoffFor(l.failures))
	return false
}

// backoffFor doubles per consecutive failure, to a cap.
//
// The first failure costs half a second, which nobody typing a password
// notices. The tenth costs fifteen, which makes an online guessing attack
// pointless without ever refusing the person who owns the machine.
func backoffFor(failures int) time.Duration {
	d := loginBackoffStart
	for i := 1; i < failures && d < loginBackoffMax; i++ {
		d *= 2
	}
	return min(d, loginBackoffMax)
}
