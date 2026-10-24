package pow

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/guard/replay"
)

type fakeClock struct {
	ns atomic.Int64
}

func newFakeClock() *fakeClock {
	c := &fakeClock{}
	c.ns.Store(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano())
	return c
}

func (c *fakeClock) Now() time.Time          { return time.Unix(0, c.ns.Load()) }
func (c *fakeClock) Advance(d time.Duration) { c.ns.Add(int64(d)) }

var testKey = []byte("0123456789abcdef0123456789abcdef")

func mustNew(t testing.TB, c Config) *Challenger {
	t.Helper()
	ch, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	return ch
}

func newTest(t testing.TB, clk *fakeClock, difficulty int) *Challenger {
	t.Helper()
	c, err := New(Config{Now: clk.Now, Key: testKey, Difficulty: difficulty, TTL: time.Minute, ReplayCapacity: 64})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func solve(t testing.TB, token string) uint64 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := Solve(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// unsolved returns a solution that does not meet token's difficulty.
func unsolved(t testing.TB, token string) uint64 {
	t.Helper()
	for s := uint64(0); ; s++ {
		if ok, err := Check(token, s); err != nil {
			t.Fatal(err)
		} else if !ok {
			return s
		}
	}
}

func TestRoundTrip(t *testing.T) {
	clk := newFakeClock()
	c := newTest(t, clk, 8)
	binding := []byte("203.0.113.7 login")
	token, err := c.Issue(binding)
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != TokenLen {
		t.Fatalf("token length %d, want %d", len(token), TokenLen)
	}
	ch, err := Parse(token)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Version != Version || ch.Difficulty != 8 || !ch.Expires.Equal(clk.Now().Add(time.Minute)) {
		t.Fatalf("parsed %+v", ch)
	}
	s := solve(t, token)
	if ok, _ := Check(token, s); !ok {
		t.Fatal("Check rejects the solution Solve found")
	}
	if err := c.Verify(token, unsolved(t, token), binding); !errors.Is(err, ErrInsufficientWork) {
		t.Fatalf("unsolved: %v", err)
	}
	if err := c.Verify(token, s, []byte("203.0.113.8 login")); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("other binding: %v", err)
	}
	if err := c.Verify(token, s, binding); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := c.Verify(token, s, binding); !errors.Is(err, ErrReplay) {
		t.Fatalf("reuse: %v, want ErrReplay", err)
	}
	// Solutions are not unique: another solution of the same challenge
	// is still a reuse.
	for s2 := s + 1; ; s2++ {
		if ok, _ := Check(token, s2); ok {
			if err := c.Verify(token, s2, binding); !errors.Is(err, ErrReplay) {
				t.Fatalf("reuse with another solution: %v", err)
			}
			break
		}
	}
}

func TestExpiry(t *testing.T) {
	clk := newFakeClock()
	c := newTest(t, clk, 4)
	token, _ := c.Issue(nil)
	s := solve(t, token)
	clk.Advance(time.Minute + time.Millisecond)
	if err := c.Verify(token, s, nil); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired: %v", err)
	}
	// A challenge whose expiry lies beyond the TTL was not issued by
	// this configuration.
	long, err := New(Config{Now: clk.Now, Key: testKey, Difficulty: 4, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	token, _ = long.Issue(nil)
	if err := c.Verify(token, solve(t, token), nil); !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("expiry beyond TTL: %v", err)
	}
}

func TestClockSkew(t *testing.T) {
	ahead, behind := newFakeClock(), newFakeClock()
	ahead.Advance(DefaultSkew)
	issuer := newTest(t, ahead, 4)
	verifier := newTest(t, behind, 4)
	token, _ := issuer.Issue(nil)
	s := solve(t, token)
	if err := verifier.Verify(token, s, nil); err != nil {
		t.Fatalf("issuer ahead by the skew: %v", err)
	}
	ahead.Advance(10 * time.Millisecond)
	token, _ = issuer.Issue(nil)
	if err := verifier.Verify(token, solve(t, token), nil); !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("issuer ahead by more than the skew: %v", err)
	}
	if _, err := New(Config{Key: testKey, Skew: -1}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatal(err)
	}
}

func TestTamper(t *testing.T) {
	clk := newFakeClock()
	c := newTest(t, clk, 1)
	token, _ := c.Issue([]byte("b"))
	raw, _, err := decode(token)
	if err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		for _, bit := range []byte{0x01, 0x80} {
			mod := raw
			mod[i] ^= bit
			tok := enc.EncodeToString(mod[:])
			s := uint64(0)
			if _, ch, err := decode(tok); err == nil {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				if ch.Difficulty <= 20 {
					s, _ = Solve(ctx, tok)
				}
				cancel()
			}
			if err := c.Verify(tok, s, []byte("b")); err == nil {
				t.Fatalf("byte %d bit %#x flipped: accepted", i, bit)
			}
		}
	}
}

func TestMalformed(t *testing.T) {
	clk := newFakeClock()
	c := newTest(t, clk, 1)
	token, _ := c.Issue(nil)
	raw, _, _ := decode(token)
	bad := map[string]error{
		"":                            ErrMalformed,
		token[:TokenLen-1]:            ErrMalformed,
		token + "A":                   ErrMalformed,
		strings.Repeat("!", TokenLen): ErrMalformed,
	}
	v2 := raw
	v2[0] = 2
	bad[enc.EncodeToString(v2[:])] = ErrVersion
	d0 := raw
	d0[1] = 0
	bad[enc.EncodeToString(d0[:])] = ErrMalformed
	big := raw
	big[2] = 0x80
	bad[enc.EncodeToString(big[:])] = ErrMalformed
	// A non-canonical final character decodes to the same bytes in a
	// lenient decoder; the strict one rejects it.
	last := token[TokenLen-1]
	alt := strings.IndexByte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", last) ^ 1
	bad[token[:TokenLen-1]+string("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[alt])] = ErrMalformed
	for tok, want := range bad {
		if err := c.Verify(tok, 0, nil); !errors.Is(err, want) {
			t.Errorf("Verify(%q) = %v, want %v", tok, err, want)
		}
		if _, err := Parse(tok); !errors.Is(err, want) {
			t.Errorf("Parse(%q) = %v, want %v", tok, err, want)
		}
		if _, err := Solve(context.Background(), tok); !errors.Is(err, want) {
			t.Errorf("Solve(%q) = %v, want %v", tok, err, want)
		}
	}
}

func TestIssueDifficulty(t *testing.T) {
	clk := newFakeClock()
	c := newTest(t, clk, 20)
	if c.Difficulty() != 20 {
		t.Fatal(c.Difficulty())
	}
	token, err := c.IssueDifficulty(nil, 3)
	if err != nil {
		t.Fatal(err)
	}
	if ch, _ := Parse(token); ch.Difficulty != 3 {
		t.Fatalf("difficulty %d", ch.Difficulty)
	}
	if err := c.Verify(token, solve(t, token), nil); err != nil {
		t.Fatal(err)
	}
	for _, d := range []int{0, -1, 256} {
		if _, err := c.IssueDifficulty(nil, d); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("difficulty %d: %v", d, err)
		}
	}
}

func TestSolveCancel(t *testing.T) {
	clk := newFakeClock()
	c := newTest(t, clk, 255)
	token, _ := c.Issue(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := Solve(ctx, token); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Solve = %v", err)
	}
}

func TestConfig(t *testing.T) {
	bad := []Config{
		{Key: []byte("short")},
		{Key: make([]byte, 32)},
		{Key: testKey, Difficulty: 256},
		{Key: testKey, Difficulty: -1},
		{Key: testKey, TTL: time.Microsecond},
		{Key: testKey, TTL: -time.Second},
		{Key: testKey, ReplayCapacity: -1},
		{Key: testKey, TTL: 1<<63 - 1},
		{Key: testKey, TTL: time.Hour, Skew: 1<<63 - 1},
	}
	for _, cfg := range bad {
		if _, err := New(cfg); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("New(%+v) = %v", cfg, err)
		}
	}
	key := append([]byte(nil), testKey...)
	clk := newFakeClock()
	c, err := New(Config{Now: clk.Now, Key: key, Difficulty: 1})
	if err != nil {
		t.Fatal(err)
	}
	token, _ := c.Issue(nil)
	key[0] ^= 1 // New copied the key
	if err := c.Verify(token, solve(t, token), nil); err != nil {
		t.Fatal(err)
	}
	// A generated key differs per Challenger.
	a := mustNew(t, Config{Now: clk.Now, Difficulty: 1})
	b := mustNew(t, Config{Now: clk.Now, Difficulty: 1})
	token, _ = a.Issue(nil)
	if err := b.Verify(token, solve(t, token), nil); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("random keys shared: %v", err)
	}
}

func TestUninitialized(t *testing.T) {
	var c Challenger
	if _, err := c.Issue(nil); !errors.Is(err, ErrUninitialized) {
		t.Error(err)
	}
	if _, err := c.IssueDifficulty(nil, 1); !errors.Is(err, ErrUninitialized) {
		t.Error(err)
	}
	if err := c.Verify(strings.Repeat("A", TokenLen), 0, nil); !errors.Is(err, ErrUninitialized) {
		t.Error(err)
	}
	var n *Challenger
	if err := n.Verify("", 0, nil); !errors.Is(err, ErrUninitialized) || n.Difficulty() != 0 {
		t.Error(err)
	}
}

func TestReplayFull(t *testing.T) {
	clk := newFakeClock()
	c, err := New(Config{Now: clk.Now, Key: testKey, Difficulty: 1, TTL: time.Minute, ReplayCapacity: 1})
	if err != nil {
		t.Fatal(err)
	}
	first, _ := c.Issue(nil)
	clk.Advance(time.Millisecond)
	second, _ := c.Issue(nil)
	s1, s2 := solve(t, first), solve(t, second)
	if err := c.Verify(second, s2, nil); err != nil {
		t.Fatal(err)
	}
	// The window is full: the older challenge is rejected as expired,
	// and the remembered one still as a replay.
	if err := c.Verify(first, s1, nil); !errors.Is(err, ErrExpired) {
		t.Fatalf("older challenge on a full window: %v", err)
	}
	if err := c.Verify(second, s2, nil); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay: %v", err)
	}
}

func TestConcurrentVerify(t *testing.T) {
	clk := newFakeClock()
	c := newTest(t, clk, 4)
	token, _ := c.Issue(nil)
	s := solve(t, token)
	var ok atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if c.Verify(token, s, nil) == nil {
				ok.Add(1)
			}
		})
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("challenge accepted %d times", ok.Load())
	}
}

func FuzzVerify(f *testing.F) {
	clk := newFakeClock()
	c := newTest(f, clk, 1)
	token, _ := c.Issue([]byte("x"))
	f.Add(token, uint64(0), []byte("x"))
	f.Add(strings.Repeat("A", TokenLen), uint64(1), []byte(nil))
	f.Add("", uint64(0), []byte(nil))
	f.Fuzz(func(t *testing.T, tok string, s uint64, binding []byte) {
		ch, perr := Parse(tok)
		err := c.Verify(tok, s, binding)
		if perr != nil && !errors.Is(err, perr) {
			t.Fatalf("Parse: %v, Verify: %v", perr, err)
		}
		if perr == nil && ch.Version != Version {
			t.Fatalf("parsed version %d", ch.Version)
		}
		if err == nil && !authentic(tok, binding) {
			t.Fatalf("forged token %q accepted", tok)
		}
		if ok, cerr := Check(tok, s); perr == nil && (cerr != nil || (err == nil && !ok)) {
			t.Fatalf("Check = %v, %v", ok, cerr)
		}
	})
}

func BenchmarkIssue(b *testing.B) {
	c := mustNew(b, Config{Key: testKey})
	binding := []byte("203.0.113.7 login")
	b.ReportAllocs()
	for b.Loop() {
		_, _ = c.Issue(binding)
	}
}

func BenchmarkVerify(b *testing.B) {
	c := mustNew(b, Config{Key: testKey, Difficulty: 1, ReplayCapacity: 1 << 20})
	binding := []byte("203.0.113.7 login")
	b.ReportAllocs()
	for b.Loop() {
		b.StopTimer()
		token, _ := c.Issue(binding)
		s, _ := Solve(context.Background(), token)
		b.StartTimer()
		if err := c.Verify(token, s, binding); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyRejectWork(b *testing.B) {
	c := mustNew(b, Config{Key: testKey, Difficulty: 30})
	token, _ := c.Issue(nil)
	b.ReportAllocs()
	for b.Loop() {
		_ = c.Verify(token, 1, nil)
	}
}

func BenchmarkSolve16(b *testing.B) {
	c := mustNew(b, Config{Key: testKey, Difficulty: 16})
	b.ReportAllocs()
	for b.Loop() {
		b.StopTimer()
		token, _ := c.Issue(nil)
		b.StartTimer()
		_, _ = Solve(context.Background(), token)
	}
}

// authentic recomputes a token's MAC independently of Challenger.sign.
func authentic(token string, binding []byte) bool {
	raw, err := enc.DecodeString(token)
	if err != nil || len(raw) != rawLen {
		return false
	}
	m := hmac.New(sha256.New, testKey)
	m.Write([]byte("guard/pow/v1\x00"))
	m.Write(raw[:headerLen])
	m.Write(binding)
	return hmac.Equal(m.Sum(nil), raw[headerLen:])
}

// mapStore is a Store shared by several Challengers, as a database would
// be.
type mapStore struct {
	err  error
	seen map[ID]time.Time
	mu   sync.Mutex
}

func (m *mapStore) MarkUsed(id ID, expires time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return false, m.err
	}
	if _, ok := m.seen[id]; ok {
		return false, nil
	}
	m.seen[id] = expires
	return true, nil
}

func TestSharedStore(t *testing.T) {
	clk := newFakeClock()
	store := &mapStore{seen: map[ID]time.Time{}}
	a := mustNew(t, Config{Now: clk.Now, Key: testKey, Difficulty: 4, Store: store})
	b := mustNew(t, Config{Now: clk.Now, Key: testKey, Difficulty: 4, Store: store})
	token, _ := a.Issue(nil)
	s := solve(t, token)
	if err := b.Verify(token, s, nil); err != nil {
		t.Fatal(err)
	}
	if err := a.Verify(token, s, nil); !errors.Is(err, ErrReplay) {
		t.Fatalf("reuse on another instance: %v", err)
	}
	ch, _ := Parse(token)
	if exp, ok := store.seen[ch.Nonce]; !ok || !exp.Equal(ch.Expires) {
		t.Fatalf("store holds %v, %v", exp, ok)
	}
	// A failing store rejects, and errors it reports pass through.
	token, _ = a.Issue(nil)
	s = solve(t, token)
	store.err = errors.New("database down")
	if err := a.Verify(token, s, nil); !errors.Is(err, ErrStore) || !errors.Is(err, store.err) {
		t.Fatalf("failing store: %v", err)
	}
	store.err = ErrExpired
	if err := a.Verify(token, s, nil); !errors.Is(err, ErrExpired) || errors.Is(err, ErrStore) {
		t.Fatalf("store reporting expiry: %v", err)
	}
	store.err = nil
	if err := a.Verify(token, s, nil); err != nil {
		t.Fatalf("after the store recovered: %v", err)
	}
}

func TestMemoryStoreShared(t *testing.T) {
	clk := newFakeClock()
	m, err := NewMemoryStore(replay.Config{Now: clk.Now, Window: time.Minute, Skew: time.Second, Capacity: 16})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewMemoryStore(replay.Config{}); err == nil {
		t.Fatal("NewMemoryStore accepted a zero window")
	}
	old := mustNew(t, Config{Now: clk.Now, Key: testKey, Difficulty: 2, TTL: time.Minute, Store: m})
	rotated := mustNew(t, Config{Now: clk.Now, Key: []byte("fedcba9876543210fedcba9876543210"), Difficulty: 2, TTL: time.Minute, Store: m})
	token, _ := old.Issue(nil)
	s := solve(t, token)
	if err := old.Verify(token, s, nil); err != nil {
		t.Fatal(err)
	}
	if fresh, err := m.MarkUsed(mustParse(t, token).Nonce, mustParse(t, token).Expires); fresh || err != nil {
		t.Fatalf("MarkUsed of a used id = %v, %v", fresh, err)
	}
	if fresh, err := m.MarkUsed(ID{1}, clk.Now().Add(-time.Second)); fresh || !errors.Is(err, ErrExpired) {
		t.Fatalf("expired id: %v, %v", fresh, err)
	}
	if fresh, err := m.MarkUsed(ID{2}, clk.Now().Add(time.Hour)); fresh || !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("future id: %v, %v", fresh, err)
	}
	// Another Challenger, as after a key rotation, sees the same use.
	if err := rotated.Verify(token, s, nil); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("other key: %v", err)
	}
	token, _ = rotated.Issue(nil)
	s = solve(t, token)
	if err := rotated.Verify(token, s, nil); err != nil {
		t.Fatal(err)
	}
	if fresh, _ := m.MarkUsed(mustParse(t, token).Nonce, mustParse(t, token).Expires); fresh {
		t.Fatal("rotated Challenger's use not recorded in the shared store")
	}
}

func mustParse(t testing.TB, token string) Challenge {
	t.Helper()
	ch, err := Parse(token)
	if err != nil {
		t.Fatal(err)
	}
	return ch
}

func TestVerifyAllocs(t *testing.T) {
	if raceEnabled {
		t.Skip("sync.Pool drops items in race builds")
	}
	clk := newFakeClock()
	c := mustNew(t, Config{Now: clk.Now, Key: testKey, Difficulty: 1, ReplayCapacity: 4096})
	binding := []byte("203.0.113.7 login")
	type solved struct {
		token string
		s     uint64
	}
	list := make([]solved, 3000)
	for i := range list {
		token, _ := c.Issue(binding)
		list[i] = solved{token, solve(t, token)}
	}
	i := 0
	verify := func() {
		if err := c.Verify(list[i].token, list[i].s, binding); err != nil {
			t.Fatal(err)
		}
		i++
	}
	for range 1000 {
		verify()
	}
	if n := testing.AllocsPerRun(1000, verify); n != 0 {
		t.Fatalf("Verify allocates %v times", n)
	}
}
