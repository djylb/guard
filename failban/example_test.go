package failban_test

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/djylb/guard/failban"
)

var errTooManyAttempts = errors.New("too many attempts")

// A login limited per account and per client network.
type login struct {
	// Bans by account name keep the default LockShard policy, so that
	// made-up names cannot push out the ban on a real account.
	users *failban.Limiter[string]
	// Bans by IP prefix may end the soonest-ending ban when the table is
	// full, rather than lock out a whole shard.
	ips *failban.Limiter[netip.Prefix]
}

func newLogin() (*login, error) {
	users, err := failban.New[string](failban.Config{
		Threshold:      5,
		Window:         15 * time.Minute,
		BanDuration:    time.Minute,
		MaxBanDuration: time.Hour, // repeat offenders: 1m, 2m, 4m, ... 1h
	})
	if err != nil {
		return nil, err
	}
	ips, err := failban.New[netip.Prefix](failban.Config{Threshold: 20, Full: failban.EvictSoonest})
	if err != nil {
		return nil, err
	}
	return &login{users: users, ips: ips}, nil
}

func (l *login) check(remoteAddr, name string, password func() bool) error {
	prefix, err := failban.PrefixLen{V4: 32, V6: 64}.OfRemote(remoteAddr)
	if err != nil {
		return err
	}
	// Reserve the client first: a refused client does not touch the
	// account limiter.
	ip := l.ips.Attempt(prefix)
	if !ip.Allowed() {
		// Over HTTP: 429 with Retry-After set to this many seconds.
		_ = ip.RetryAfter() / time.Second
		return errTooManyAttempts
	}
	user := l.users.Attempt(name)
	if !user.Allowed() {
		ip.Release()
		_ = user.RetryAfter() / time.Second
		return errTooManyAttempts
	}
	if !password() { // the slow check runs at most Threshold times at once
		ip.Fail()
		if r := user.Fail(); r.Started {
			fmt.Printf("%s banned (offence %d)\n", name, r.Offences)
		}
		return errors.New("wrong password")
	}
	ip.Release()   // a success does not clear the prefix's failures
	user.Succeed() // but proves the account is the caller's
	return nil
}

func Example() {
	l, err := newLogin()
	if err != nil {
		panic(err)
	}
	for range 6 {
		fmt.Println(l.check("198.51.100.7:4321", "alice", func() bool { return false }))
	}
	fmt.Println(l.users.IsBanned("alice"), l.users.IsBanned("bob"))
	// Output:
	// wrong password
	// wrong password
	// wrong password
	// wrong password
	// alice banned (offence 1)
	// wrong password
	// too many attempts
	// true false
}

func ExamplePrefixLen() {
	// Key IPv4 clients by address and IPv6 clients by /64.
	host := failban.PrefixLen{V4: 32, V6: 64}
	p, err := host.OfRemote("[2001:db8::7]:51234")
	if err != nil {
		panic(err)
	}
	fmt.Println(p)
	// Output: 2001:db8::/64
}

func ExampleLimiter_Ban() {
	l, err := failban.New[string](failban.Config{})
	if err != nil {
		panic(err)
	}
	// Restore bans saved with Bans before a restart, or ban by hand.
	saved := []failban.Ban[string]{{Key: "mallory", Until: time.Now().Add(time.Hour), Offences: 3}}
	for _, b := range saved {
		if err := l.Ban(b); err != nil {
			fmt.Println(err)
		}
	}
	fmt.Println(l.IsBanned("mallory"))
	// Output: true
}
