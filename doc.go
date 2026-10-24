// Package guard is the root of a set of security building blocks for
// network services and their admin pages. It holds no code; each
// component is a small package that depends on the standard library only:
//
//   - replay rejects (timestamp, nonce) pairs seen within a time window,
//     with bounded memory and no allocation per check.
//   - pow issues stateless, signed proof-of-work challenges and verifies
//     their solutions once.
//   - failban counts failures per key, such as IP prefixes or user names,
//     and bans keys that fail too often.
//   - otp implements HOTP and TOTP one-time passwords with replay
//     protection and otpauth URIs.
//   - webguard is net/http middleware against DNS rebinding and
//     cross-site request forgery, with CSRF tokens.
//
// None of the packages starts goroutines; their memory is bounded by
// configuration and reclaimed by the calls that use it.
package guard
