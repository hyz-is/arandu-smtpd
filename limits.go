package smtpd

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"
)

const shardCount = 64

// clientKey is what a client is counted as: its IPv4 address, or the /64 of its
// IPv6 address, because a client that holds an IPv6 allocation holds more
// addresses than any limit per address could count.
func clientKey(a netip.Addr) netip.Addr {
	a = a.Unmap()
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.Addr()
	}
	return a
}

func shardOf(a netip.Addr) int {
	b := a.As16()
	h := binary.LittleEndian.Uint64(b[8:]) ^ binary.LittleEndian.Uint64(b[:8])
	h *= 0x9E3779B97F4A7C15
	return int(h >> (64 - 6))
}

// ipLimiter counts the connections each client holds. It is sharded so that
// connections from different clients do not wait for each other.
type ipLimiter struct {
	shards [shardCount]struct {
		mu sync.Mutex
		m  map[netip.Addr]int32
		_  [40]byte // keeps two shards off one cache line
	}
}

func newIPLimiter() *ipLimiter {
	l := &ipLimiter{}
	for i := range l.shards {
		l.shards[i].m = make(map[netip.Addr]int32)
	}
	return l
}

// acquire takes a slot for the client and reports whether there was one under
// max. A max of 0 or less is no limit, and takes nothing.
func (l *ipLimiter) acquire(a netip.Addr, max int) bool {
	if max <= 0 {
		return true
	}
	k := clientKey(a)
	s := &l.shards[shardOf(k)]
	s.mu.Lock()
	defer s.mu.Unlock()
	if int(s.m[k]) >= max {
		return false
	}
	s.m[k]++
	return true
}

func (l *ipLimiter) release(a netip.Addr) {
	k := clientKey(a)
	s := &l.shards[shardOf(k)]
	s.mu.Lock()
	if n := s.m[k]; n <= 1 {
		delete(s.m, k)
	} else {
		s.m[k] = n - 1
	}
	s.mu.Unlock()
}

// authGuard limits the failed AUTH attempts of each client. A client that fails
// max times within window is blocked for blockFor, and while it is blocked no
// credential is checked, even a right one: that is what stops a guessing run
// that is spread over many connections.
type authGuard struct {
	max      int
	window   time.Duration
	blockFor time.Duration
	now      func() time.Time
	shards   [shardCount]struct {
		mu        sync.Mutex
		m         map[netip.Addr]*authEntry
		nextSweep time.Time
		_         [24]byte
	}
}

type authEntry struct {
	failures     int
	windowStart  time.Time
	blockedUntil time.Time
}

func newAuthGuard(max int, window, blockFor time.Duration, now func() time.Time) *authGuard {
	g := &authGuard{max: max, window: window, blockFor: blockFor, now: now}
	for i := range g.shards {
		g.shards[i].m = make(map[netip.Addr]*authEntry)
	}
	return g
}

// blocked reports whether the client may not try to authenticate now.
func (g *authGuard) blocked(a netip.Addr) bool {
	if g == nil || g.max <= 0 {
		return false
	}
	k := clientKey(a)
	s := &g.shards[shardOf(k)]
	now := g.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.m[k]
	return e != nil && now.Before(e.blockedUntil)
}

// fail records a failed attempt and reports whether the client is now blocked.
func (g *authGuard) fail(a netip.Addr) bool {
	if g == nil || g.max <= 0 {
		return false
	}
	k := clientKey(a)
	s := &g.shards[shardOf(k)]
	now := g.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	g.sweep(s.m, &s.nextSweep, now)
	e := s.m[k]
	if e == nil {
		e = &authEntry{windowStart: now}
		s.m[k] = e
	}
	if now.Sub(e.windowStart) > g.window {
		e.failures, e.windowStart = 0, now
	}
	e.failures++
	if e.failures >= g.max {
		e.blockedUntil = now.Add(g.blockFor)
		e.failures, e.windowStart = 0, now
		return true
	}
	return false
}

// sweep drops the entries that no longer count for anything. It runs at most
// once a minute for a shard, and only when that shard is used.
func (g *authGuard) sweep(m map[netip.Addr]*authEntry, next *time.Time, now time.Time) {
	if now.Before(*next) {
		return
	}
	*next = now.Add(time.Minute)
	for k, e := range m {
		if now.After(e.blockedUntil) && now.Sub(e.windowStart) > g.window {
			delete(m, k)
		}
	}
}

// unblock forgets a client's failures and its block.
func (g *authGuard) unblock(a netip.Addr) {
	if g == nil {
		return
	}
	k := clientKey(a)
	s := &g.shards[shardOf(k)]
	s.mu.Lock()
	delete(s.m, k)
	s.mu.Unlock()
}
