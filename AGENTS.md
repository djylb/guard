# AGENTS.md

- Before you finish, `gofmt -l .` must print nothing and `go vet ./...`,
  `go test -race ./...` and the js/wasm tests
  (`GOOS=js GOARCH=wasm go test ./...` with `$(go env GOROOT)/lib/wasm` on
  `PATH`) must pass, and each fuzz target must survive a short run.
- Standard library only, also for tests. Only `webguard` imports net/http;
  code shared by packages lives in `internal/`; register every new
  package in `deps_test.go`.
- No background goroutines. Memory is bounded by configuration and
  reclaimed by the calls that use it.
- Fail closed: a zero value or an invalid configuration denies or returns
  an error, never panics and never accepts.
- A replay window entry, challenge or one-time code is never accepted
  twice within its validity, also when the tables are full or the wall
  clock steps; time limits use the monotonic clock. CSRF tokens are the
  exception by design: reusable within their MaxAge.
- Compare MACs, codes and tokens in constant time; draw secrets and nonces
  from crypto/rand.
- Checks (replay, ban, challenge, one-time password, CSRF token and
  Guard request checks) stay allocation-free, rejections included: use
  preallocated errors. Document any allocation left inside the standard
  library.
- Every `Config` decodes from JSON: snake_case fields, durations as
  `time.ParseDuration` strings, enums by their `String` names, unknown
  fields rejected.
- No `Must` constructors; one way to do each thing, the same across
  packages.
- Errors meant for logs may say why a check failed; the docs tell callers
  not to pass that difference on to the peer.
- Tests must not leak goroutines or timers.
- The README, docs and commits name no other project and quote no benchmark
  numbers.
- Commit subjects are short, English and imperative.
- Never commit host names, IP addresses or credentials.
