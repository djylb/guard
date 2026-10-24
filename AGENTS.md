# AGENTS.md

- Before you finish, `gofmt -l .` must print nothing and `go vet ./...`,
  `go test -race ./...` and the js/wasm tests
  (`GOOS=js GOARCH=wasm go test ./...` with `$(go env GOROOT)/lib/wasm` on
  `PATH`) must pass, and each fuzz target must survive a short run.
- Standard library only, also for tests. Only `webguard` imports net/http;
  register every new package in `deps_test.go`.
- No background goroutines. Memory is bounded by configuration and
  reclaimed by the calls that use it.
- Fail closed: a zero value or an invalid configuration denies or returns
  an error, never panics and never accepts.
- A replay window, challenge, code or token is never accepted twice within
  its validity, also when the tables are full or the wall clock steps; time
  limits use the monotonic clock.
- Compare MACs, codes and tokens in constant time; draw secrets and nonces
  from crypto/rand.
- Checks (replay, ban, challenge and token verification) stay
  allocation-free.
- Errors meant for logs may say why a check failed; the docs tell callers
  not to pass that difference on to the peer.
- Tests must not leak goroutines or timers.
- The README, docs and commits name no other project and quote no benchmark
  numbers.
- Commit subjects are short, English and imperative.
- Never commit host names, IP addresses or credentials.
