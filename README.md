# guard

Security building blocks for Go network services and their admin pages:
replay protection, proof-of-work challenges, failure limiting and bans,
one-time passwords, and HTTP middleware against DNS rebinding and CSRF.

- Standard library only, with no dependencies, tests included.
- Small, focused packages that can be used on their own and compose.
- No background goroutines: memory is bounded by configuration and
  reclaimed deterministically by the calls that use it.
- Safe for concurrent use, with sharded locks on the hot paths. Replay,
  ban, challenge, one-time password, CSRF token and request checks do not
  allocate, also when they reject. The exception is a cross-origin check
  of a request that carries Origin but no Sec-Fetch-Site, where
  `http.CrossOriginProtection` parses the Origin.
- Zero values never panic and never run with an empty key: types that
  hold a key report an error, a zero `failban.Limiter` reports every key
  banned, and a zero `webguard.Guard` or `CSRF` rejects requests.
  All-zero and short keys are refused.

```
go get github.com/djylb/guard
```

Requires Go 1.26 or later.

| Package    | Purpose                                                        |
|------------|----------------------------------------------------------------|
| `replay`   | Reject a (timestamp, nonce) pair seen within a time window     |
| `pow`      | Stateless, signed proof-of-work challenges, each usable once   |
| `failban`  | Count failures per key and ban keys that fail too often        |
| `otp`      | HOTP and TOTP (RFC 4226, RFC 6238) with replay protection      |
| `webguard` | net/http middleware: Host allowlist, cross-origin checks, CSRF |

`pow` uses `replay`; the other packages are independent, and only
`webguard` imports `net/http`.

Every `Config` also decodes from JSON, so it can sit in a service's config
file. Durations are strings such as `"15m"`, policies are names such as
`"EvictSoonest"`, keys are standard base64, and unknown fields and nulls
are errors rather than silent defaults. A key must be given, or asked for
as `"random"`, valid only in this process:

```go
var conf struct {
	Login failban.Config  `json:"login"` // {"threshold": 5, "window": "15m", "full": "LockShard"}
	Admin webguard.Config `json:"admin"` // {"hosts": ["admin.example.com"], "trusted_proxies": ["10.0.0.2"]}
}
err := json.Unmarshal(data, &conf)
```

## replay

A `Window` accepts each nonce once while its timestamp lies within the
window, and rejects every later copy.

```go
w, err := replay.New(replay.Config{
	Window: 30 * time.Second, // how old a timestamp may be
	Skew:   5 * time.Second,  // how far ahead a sender's clock may run
})
if err != nil {
	return err
}
// After authenticating the message, for example by its MAC:
if err := w.Check(msg.Time, msg.Nonce); err != nil {
	return err // replay.ErrReplay, ErrStale, ErrFuture, ErrFull
}
```

- **Bounded memory.** At most `Capacity` nonces (64 Ki by default). Memory
  grows with use, at about 80 bytes per nonce, so some 5 MiB when full at
  the default. Pages that see few messages, such as a login form, can set
  `Capacity: 4096`. A nonce is remembered for `Window + Skew` and
  forgotten in acceptance order, at amortised O(1) per check.
- **When full, never a replay.** With `ShrinkWindow` (the default), a full
  shard forgets its oldest nonce early and from then on rejects every
  timestamp at or below that nonce's as stale: the window shrinks rather
  than reopens. `RejectNew` refuses new nonces with `ErrFull` instead.
- **Clocks.** Expiry runs on the monotonic clock. A forgotten nonce stays
  rejected even if the wall clock is stepped back.
- Nonces are identified by a 128-bit keyed hash, so a check does not
  allocate. While a nonce is remembered, it is rejected with any
  timestamp.
- **Observability.** `Stats` reports the nonces remembered, the capacity,
  and how many nonces `ShrinkWindow` forgot early: if that grows,
  `Capacity` is too small for the load.

## pow

A `Challenger` issues challenges that are signed with HMAC-SHA-256 and
bound to a context, such as the client's IP address and the form. The
server keeps no state per challenge until it accepts one.

```go
c, err := pow.New(pow.Config{
	Key:        key, // ≥ 16 bytes, shared by servers; nil = random per process
	Difficulty: 18,  // leading zero bits; 2^18 hashes on average
	TTL:        2 * time.Minute,
	Skew:       2 * time.Second, // how far ahead another issuing server's clock may run
})

token, err := c.Issue(clientIP, "login")            // send to the client
solution, err := pow.Solve(ctx, token)              // client side
err = c.Verify(token, solution, clientIP, "login")  // pow.ErrReplay on reuse
```

Verify checks the expiry, then the work with one SHA-256 hash, then the
signature (compared in constant time), and finally whether the challenge
was already used, in a `Store`. A successful Verify does not allocate.
The binding is a list of strings, each length-prefixed in the MAC, so
`("ab", "c")` and `("a", "bc")` differ. The default store holds up to
`ReplayCapacity` (64 Ki) challenges and grows with use to about 5 MiB;
set a few thousand for a single login form.

To rotate the key, make the new one `Key` and keep the old one in
`PreviousKeys` for one TTL: challenges signed with either verify.

The default store is a `MemoryStore`, a bounded `replay.Window` in
process memory. Challengers in one process may share a `MemoryStore` if
the TTL plus skew of each fits within the store's window plus skew; `New`
refuses one that does not. When several instances share a key, give them one shared
`Store`, for example a key-value database with an atomic set-if-absent:

```go
type Store interface {
	// Exactly one call per id reports fresh; keep id until expires
	// (plus the clock lag of verifying servers); return an error when unsure.
	MarkUsed(id pow.ID, expires time.Time) (fresh bool, err error)
}
```

Store errors reject the challenge (`pow.ErrStore`). `IssueDifficulty` raises
the cost per challenge, for example while the service is under attack.
`Parse` and `Check` let clients read and test tokens. `MemoryStore.Stats`
reports the use of a store you create yourself.

Browser clients can solve challenges themselves. A token is the unpadded
base64url encoding of `version (1) | difficulty (1) | expiry ms (8) |
nonce (16) | MAC (32)`. A solution is a 64-bit number `s` such that
`SHA-256(token bytes || s as 8 big-endian bytes)` starts with
`difficulty` zero bits.

## failban

A `Limiter[K]` is generic over the key type, so there is no guessing
whether a string is an IP address or a user name.

```go
// Name-keyed bans keep the default LockShard policy, so made-up names
// cannot push out the ban on a real account (see "Full ban table").
users, err := failban.New[string](failban.Config{
	Threshold:      5,
	Window:         15 * time.Minute,
	BanDuration:    time.Minute,
	MaxBanDuration: 24 * time.Hour, // doubles for repeat offenders
})
ips, err := failban.New[netip.Prefix](failban.Config{Threshold: 20, Full: failban.EvictSoonest})

prefix, err := failban.PrefixLen{V4: 32, V6: 64}.OfRemote(r.RemoteAddr)
ip, user := ips.Attempt(prefix), users.Attempt(name)
if !ip.Allowed() || !user.Allowed() {
	ip.Release() // release whichever reservation was made
	user.Release()
	retry := max(ip.RetryAfter(), user.RetryAfter())
	w.Header().Set("Retry-After", strconv.Itoa(int(retry/time.Second)))
	http.Error(w, "too many attempts", http.StatusTooManyRequests)
	return
}
if !checkPassword(name, password) { // slow, so at most Threshold run at once
	ip.Fail()
	if res := user.Fail(); res.Started {
		log.Printf("%s banned until %v (offence %d)", name, res.Until, res.Offences)
	}
	return
}
ip.Release()   // keeps the prefix's failures
user.Succeed() // clears the account's failures
```

- **Attempts are reserved atomically.** Checking `IsBanned` before a slow
  password check and calling `Fail` after it is racy: many concurrent
  guesses all pass the check. `Attempt` admits an attempt only while the
  key's failures plus its attempts in flight are below `Threshold`.
  Settle each attempt once: `Fail` counts a failure, `Release` releases
  the reservation without clearing earlier failures, and `Succeed` also
  clears them. Use `Succeed` only where the success proves the key is
  the caller's, such as an account name. On an IP limiter, an attacker
  could clear its prefix by logging into its own account. `IsBanned` and
  `BannedUntil` are read-only, for display.
- **Settled once.** Each reservation has an identity, so a copied
  `Attempt` cannot settle it twice and let more than `Threshold` attempts
  run. Keys without failures reuse counters, so attempts do not allocate.
- **Retry-After.** `RetryAfter` of a refused attempt is the time until
  its ban ends, in whole seconds and at least one.
- **Counting.** Failures are counted in eight time buckets per key, which
  together cover between `Window` and 8/7 of it, so counting errs towards
  banning. Timing has nanosecond resolution on the monotonic clock.
- **Bans.** A ban lasts `BanDuration`. If `MaxBanDuration` is longer, the
  next ban within `Cooldown` of the last one lasts twice as long, up to
  `MaxBanDuration`. A `Result` tells whether a failure started a ban, for
  logging each ban once.
- **Bounded memory.** When `MaxPending` pending counters are reached, the
  least recently updated one is evicted. Flooding can reset pending
  counts this way, but never lifts a ban.
- **Full ban table.** Records of ended bans are dropped first. When all
  `MaxBans` records are active bans, `Full` decides:
  - `LockShard` (default) keeps every ban and reports every key of the
    shard as banned until its earliest ban ends. No ban ever ends early,
    but filling the table locks out every legitimate user of the shard.
    It is the default because keys that cost an attacker nothing, such as
    made-up user names, could otherwise fill the table and lift the ban on
    a targeted account.
  - `EvictSoonest` ends the ban that would end soonest, and keeps that key
    one failure away from its next, longer ban. Use it for limiters keyed
    by IP prefix. An attacker who can fill such a table controls many
    prefixes, so the bans that end early are mostly its own oldest ones,
    while legitimate users are unaffected.

  A key that reaches `Threshold` during a lockdown is reported banned and
  gets its ban as soon as a record is free.
- **Persistence and manual bans.** `Bans` lists the active bans; `Ban`
  bans a key until a given time, for an administrator or to restore the
  saved list after a restart. Pending failures and the offences of ended
  bans are not saved.
- **Deterministic cleanup.** Cleanup is done by the calls that change a
  shard, plus an optional `Sweep`. Nothing runs at random or in the
  background, and every per-key operation takes amortised constant time.
- **Observability.** `Stats` returns sizes (pending, banned, cooling,
  waiting, locked shards) and counters (failures, bans started, attempts
  refused, bans evicted). `Failures` returns a key's count. `Unban` and
  `Reset` are for administrators.

Key IPv6 clients by prefix (`/64` or `/56`), not by single address: a
single host may hold billions of addresses. A single `/48` holds 65536
`/64`s, so put a limiter keyed by a wider prefix, such as
`PrefixLen{V4: 24, V6: 48}`, in front of the `/64` one to keep one network
from filling the ban table. A `PrefixLen` field left at zero means the
full address, never `/0`. Behind a reverse proxy, key on
`webguard.Guard.ClientAddr` rather than `RemoteAddr`.

## otp

```go
secret, err := otp.GenerateSecret(otp.DefaultSecretSize) // 160 bits
key := &otp.Key{Issuer: "Example", Account: "alice", Secret: secret, Skew: 1}
uri, err := key.URI() // otpauth://totp/Example:alice?secret=...; render as a QR code

// At login:
next, err := key.Verify(code, time.Now(), account.NextStep)
if err != nil {
	log.Print(err)                // otp.ErrCodeMismatch, ErrCodeReused, ErrStepAhead, ...
	return errInvalidCode         // the same answer for every rejection
}
account.NextStep = next // persist atomically (compare-and-swap)
```

- **Replay protection is part of the API.** `Verify` takes the account's
  next acceptable time step and returns the new one. A code that was
  accepted once, or any code from an earlier step, is rejected with
  `ErrCodeReused`. The value lives in the caller's account store, so
  several instances share it. `VerifyCounter` does the same for HOTP and
  resynchronises within `Skew` counters.
- **Recovery.** If the stored step lies beyond what the clock allows,
  because the server clock was once ahead or the state came from
  elsewhere, every correct code would be refused until the clock catches
  up. `Verify` reports that case as `ErrStepAhead`. Once the user has
  proved their identity another way, reset the stored step to
  `key.Step(now)`.
- **Guessing.** A six-digit code is guessed with probability 2·Skew+1 in a
  million per try. Limit tries per account and per client with
  `failban`, and answer every rejected code alike: telling
  `ErrCodeReused` from `ErrCodeMismatch` confirms that a code was right.
- Supports SHA1, SHA256 and SHA512, 6 to 10 digits, and any whole-second
  period. Secrets must be at least 128 bits (RFC 4226). Accounts enrolled
  elsewhere with 80-bit secrets can opt in with `Key.AllowShortSecret`;
  re-enrol them when possible.
- Keep `Skew` small. Each extra step costs one HMAC per check and raises
  the chance that a guess matches.
- **Strict parsing.** A code must be exactly `Digits` ASCII digits: no
  sign, no spaces. `DecodeSecret` accepts lower case and missing padding
  but nothing else. `ParseURI` rejects repeated or contradictory
  parameters.
- Codes are compared in constant time, and verification does not
  allocate.

## webguard

```go
g, err := webguard.New(webguard.LocalAdmin()) // loopback hosts and peers only
csrf, err := webguard.NewCSRF(webguard.CSRFConfig{Key: key})

handler := g.Handler(csrf.Handler(sessionID, mux))
http.ListenAndServe("127.0.0.1:8080", handler)

// In a form handler:
token, err := csrf.Token(sessionID(r)) // hidden field "csrf_token" or header X-CSRF-Token
```

`Guard` checks each request in this order:

1. **Peer.** With `LoopbackPeers`, the client may be a loopback address,
   which protects a server bound to all interfaces by mistake; `Peers`
   lists further allowed networks, such as a VPN's. With either set,
   other clients are rejected.
2. **Host allowlist.** The Host header must be one of `Hosts` (an exact
   name or IP, with or without a port), or a loopback name with
   `LoopbackHosts`. This stops DNS rebinding: a malicious site whose name
   resolves to `127.0.0.1` still sends its own name as Host.
3. **Cross-origin check** for unsafe methods, using `http.CrossOriginProtection`
   (Sec-Fetch-Site, then Origin against Host). Because the Host was
   checked first, the Origin fallback is safe. `TrustedOrigins` admits
   named origins. With `RequireOrigin`, requests that carry neither
   header must have a same-origin Referer.

**Behind a reverse proxy**, `RemoteAddr` is the proxy. List the proxies in
`TrustedProxies`: `ClientAddr` then reads the client's address from
`ForwardedHeader` (`X-Forwarded-For` by default, or the `for` parameters of
an RFC 7239 `Forwarded` header), skipping trusted proxies from the right,
so that addresses a client prepends are never believed. Every trusted host
can claim any client address: list the proxies' own addresses, not their
network. A request from a trusted proxy that names no client, such as one
whose header is missing or misnamed, is rejected rather than attributed to
the proxy.
`Peers` apply to that address, and per-client limits should key on it.
Have the proxy pass the original `Host` on and list the public names in
`Hosts`:

```go
g, err := webguard.New(webguard.Config{
	Hosts:           []string{"admin.example.com"},
	TrustedProxies:  []string{"10.0.0.2", "10.0.0.3"},
	Peers:           []string{"192.0.2.0/24"}, // optional: the office network
	RequireOrigin:   true,
	SecurityHeaders: true,
})
addr, err := g.ClientAddr(r)
```

A `Hosts` entry with a port matches only a `Host` header with that port.
Browsers leave out the default port (80, 443), so list the bare name for
a server on a default port.

`SecurityHeaders` adds `nosniff`, framing denial (`X-Frame-Options` and
CSP `frame-ancestors`), `Referrer-Policy: same-origin` and COOP.

**CSRF tokens** are HMAC-signed and bound to the session, not
double-submit cookies. A double-submit cookie can be overwritten from a
sibling subdomain or over plain HTTP. A signed token is valid only for
the session it was issued for. Each token carries a random nonce and its
issue time, so tokens differ per response, which resists compression
side channels, and expire after `MaxAge` (millisecond precision). The
handler reads the token from the `X-CSRF-Token` header or a URL-encoded
form field. It parses multipart bodies only with `MultipartForms`,
because parsing reads the whole body before the token is checked. On
browsers since 2023 the cross-origin check alone already stops CSRF;
tokens add defence in depth. `PreviousKeys` keeps tokens signed with an
old key valid while the key is rotated.

Cookie guidance: `HttpOnly`, `SameSite=Lax` or `Strict`, and over HTTPS
`Secure` with the `__Host-` prefix. SameSite does not separate sibling
subdomains, which count as the same site; the cross-origin check does.

## Security notes and limits

- `replay` only remembers what it is told. Authenticate the timestamp and
  nonce before calling `Check`, or an attacker can fill the window with
  junk. Under `ShrinkWindow`, an authenticated sender who fills a shard
  can make it reject timestamps up to `Skew` ahead of now for that long.
- `pow` raises the cost of each attempt for everyone. It does not stop an
  attacker with enough CPU, and it penalises slow clients. Pair it with
  `failban`. The default `MemoryStore` lives in process memory. A solved
  challenge can therefore be used once on each server that shares the
  key, and once more after a restart, unless the servers share a
  `Store`.
- `failban`: flooding with new keys can reset other keys' pending
  counters and reservations, never their bans. This bounds an attacker
  to `Threshold` extra attempts per key for each `MaxPending` keys
  flooded. A full ban table locks the shard for everyone (`LockShard`,
  the default) or ends the soonest-ending bans early (`EvictSoonest`, for
  IP-prefix keys). Size `MaxBans` for the attack you expect, and key by
  prefix. Settle every `Attempt`: a reservation that is never settled
  keeps counting against its key.
- `otp`: storing `next` without a compare-and-swap lets two concurrent
  logins with the same code both succeed. OTP does not protect against
  real-time phishing that relays the code.
- `webguard` does not authenticate users. It does not stop other local
  processes, which can connect to loopback directly. It trusts `Host` and
  `RemoteAddr` as `net/http` reports them, and the forwarded header only
  from `TrustedProxies`. Bodies parsed for the CSRF form field should be
  limited with `http.MaxBytesReader`.

## License

Apache License 2.0; see [LICENSE](LICENSE).
