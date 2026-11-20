package smtpd

import (
	"net/netip"
	"testing"
	"time"
)

func TestClientKey(t *testing.T) {
	a := clientKey(netip.MustParseAddr("2001:db8:1:2:aaaa:bbbb:cccc:dddd"))
	b := clientKey(netip.MustParseAddr("2001:db8:1:2:1111:2222:3333:4444"))
	c := clientKey(netip.MustParseAddr("2001:db8:1:3::1"))
	if a != b {
		t.Errorf("two addresses of one /64 are different clients: %v %v", a, b)
	}
	if a == c {
		t.Error("two /64s are one client")
	}
	if got := clientKey(netip.MustParseAddr("::ffff:192.0.2.1")); got != netip.MustParseAddr("192.0.2.1") {
		t.Errorf("an IPv4-mapped address is %v", got)
	}
}

func TestIPLimiter(t *testing.T) {
	l := newIPLimiter()
	a := netip.MustParseAddr("192.0.2.1")
	b := netip.MustParseAddr("192.0.2.2")
	if !l.acquire(a, 2) || !l.acquire(a, 2) || l.acquire(a, 2) {
		t.Fatal("limit of 2 not held")
	}
	if !l.acquire(b, 2) {
		t.Fatal("another client was refused")
	}
	l.release(a)
	if !l.acquire(a, 2) {
		t.Fatal("a released slot was not free")
	}
	l.release(a)
	l.release(a)
	l.release(a) // more releases than acquires do no harm
	if !l.acquire(a, 1) {
		t.Fatal("the counter did not return to zero")
	}
	if !l.acquire(a, 0) || !l.acquire(a, -1) {
		t.Fatal("no limit means no refusal")
	}
}

func TestAuthGuardWindowAndBlock(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	g := newAuthGuard(3, time.Minute, time.Hour, func() time.Time { return now })
	a := netip.MustParseAddr("192.0.2.1")
	if g.blocked(a) || g.fail(a) || g.fail(a) {
		t.Fatal("blocked too early")
	}
	if !g.fail(a) || !g.blocked(a) {
		t.Fatal("not blocked at the limit")
	}
	if g.blocked(netip.MustParseAddr("192.0.2.2")) {
		t.Fatal("another client is blocked")
	}
	now = now.Add(30 * time.Minute)
	if !g.blocked(a) {
		t.Fatal("block lifted early")
	}
	now = now.Add(31 * time.Minute)
	if g.blocked(a) {
		t.Fatal("block not lifted")
	}
	// Entries that no longer count are swept.
	now = now.Add(3 * time.Hour)
	// The sweep runs on the shard that is used, so use an address of a's shard.
	for i := 10; i < 255; i++ {
		b := netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})
		if shardOf(clientKey(b)) == shardOf(clientKey(a)) {
			g.fail(b)
			break
		}
	}
	for i := range g.shards {
		for k := range g.shards[i].m {
			if k == a {
				t.Fatal("a stale entry survived the sweep")
			}
		}
	}
	// A nil guard and a guard with no limit never block.
	var none *authGuard
	if none.blocked(a) || none.fail(a) {
		t.Fatal("nil guard blocked")
	}
	off := newAuthGuard(0, time.Minute, time.Hour, time.Now)
	if off.fail(a) || off.blocked(a) {
		t.Fatal("disabled guard blocked")
	}
	none.unblock(a)
}

func TestDrainLimitErrorText(t *testing.T) {
	if errDrainLimit.Error() == "" {
		t.Fatal("empty")
	}
}
