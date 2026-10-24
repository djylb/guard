package failban_test

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/djylb/guard/failban"
)

var (
	// Bans by account name keep the default LockShard policy, so that
	// made-up names cannot push out the ban on a real account.
	users = failban.MustNew[string](failban.Config{
		Threshold:      5,
		Window:         15 * time.Minute,
		BanDuration:    time.Minute,
		MaxBanDuration: time.Hour, // repeat offenders: 1m, 2m, 4m, ... 1h
	})
	// Bans by IP prefix may end the soonest-ending ban when the table is
	// full, rather than lock out a whole shard.
	ips = failban.MustNew[netip.Prefix](failban.Config{Threshold: 20, Full: failban.EvictSoonest})
)

var errTooManyAttempts = errors.New("too many attempts")

func login(remoteAddr, name string, check func() bool) error {
	prefix, err := failban.RemotePrefix(remoteAddr, failban.HostBitsV4, failban.SiteBitsV6)
	if err != nil {
		return err
	}
	ip := ips.Attempt(prefix)
	user := users.Attempt(name)
	if !ip.Allowed() || !user.Allowed() {
		ip.Done(true) // release whichever reservation was made
		user.Done(true)
		return errTooManyAttempts
	}
	ok := check() // the slow password check runs at most Threshold times at once
	ip.Done(ok)
	user.Done(ok)
	if !ok {
		return errors.New("wrong password")
	}
	return nil
}

func Example() {
	for range 6 {
		fmt.Println(login("198.51.100.7:4321", "alice", func() bool { return false }))
	}
	fmt.Println(users.IsBanned("alice"), users.IsBanned("bob"))
	// Output:
	// wrong password
	// wrong password
	// wrong password
	// wrong password
	// wrong password
	// too many attempts
	// true false
}

func ExampleRemotePrefix() {
	l := failban.MustNew[netip.Prefix](failban.Config{Threshold: 10})
	// Key IPv4 clients by address and IPv6 clients by /64.
	p, err := failban.RemotePrefix("[2001:db8::7]:51234", failban.HostBitsV4, failban.SiteBitsV6)
	if err != nil {
		panic(err)
	}
	l.Fail(p)
	fmt.Println(p, l.Failures(p))
	// Output: 2001:db8::/64 1
}
