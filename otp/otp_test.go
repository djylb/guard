package otp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"strings"
	"testing"
	"time"
)

var (
	rfcSHA1   = []byte("12345678901234567890")
	rfcSHA256 = []byte("12345678901234567890123456789012")
	rfcSHA512 = []byte("1234567890123456789012345678901234567890123456789012345678901234")
)

func TestHOTPVectors(t *testing.T) {
	// RFC 4226 appendix D.
	want := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	k := &Key{Secret: rfcSHA1, Kind: HOTP}
	for c, w := range want {
		got, err := k.CounterCode(uint64(c))
		if err != nil || got != w {
			t.Errorf("counter %d: %q, %v, want %s", c, got, err, w)
		}
	}
}

func TestTOTPVectors(t *testing.T) {
	// RFC 6238 appendix B.
	tests := []struct {
		sha1, sha256, sha512 string
		unix                 int64
	}{
		{"94287082", "46119246", "90693936", 59},
		{"07081804", "68084774", "25091201", 1111111109},
		{"14050471", "67062674", "99943326", 1111111111},
		{"89005924", "91819424", "93441116", 1234567890},
		{"69279037", "90698825", "38618901", 2000000000},
		{"65353130", "77737706", "47863826", 20000000000},
	}
	for _, tt := range tests {
		at := time.Unix(tt.unix, 0)
		for _, c := range []struct {
			want   string
			secret []byte
			alg    Algorithm
		}{{tt.sha1, rfcSHA1, SHA1}, {tt.sha256, rfcSHA256, SHA256}, {tt.sha512, rfcSHA512, SHA512}} {
			k := &Key{Secret: c.secret, Algorithm: c.alg, Digits: 8}
			got, err := k.Code(at)
			if err != nil || got != c.want {
				t.Errorf("%v at %d: %q, %v, want %s", c.alg, tt.unix, got, err, c.want)
			}
			if _, err := k.Verify(c.want, at, 0); err != nil {
				t.Errorf("%v at %d: Verify: %v", c.alg, tt.unix, err)
			}
		}
	}
}

func TestVerifyReplay(t *testing.T) {
	k := &Key{Secret: rfcSHA1, SkewSteps: 1}
	at := time.Unix(1_700_000_000, 0)
	code, _ := k.Code(at)
	cur, _ := k.Step(at)
	next, err := k.Verify(code, at, 0)
	if err != nil || next != cur+1 {
		t.Fatalf("Verify = %d, %v", next, err)
	}
	// The same code again, within its validity, is a replay.
	for _, d := range []time.Duration{0, 10 * time.Second, 30 * time.Second} {
		if n, err := k.Verify(code, at.Add(d), next); !errors.Is(err, ErrCodeReused) || n != next {
			t.Fatalf("replay after %v: %d, %v", d, n, err)
		}
	}
	// The previous step's code is also rejected once a later one was
	// used, though it lies within the skew.
	prev, _ := k.Code(at.Add(-30 * time.Second))
	if _, err := k.Verify(prev, at, next); !errors.Is(err, ErrCodeReused) {
		t.Fatalf("earlier step: %v", err)
	}
	// The next step's code is accepted.
	later, _ := k.Code(at.Add(30 * time.Second))
	if n, err := k.Verify(later, at.Add(30*time.Second), next); err != nil || n != next+1 {
		t.Fatalf("next step: %d, %v", n, err)
	}
}

func TestVerifySkew(t *testing.T) {
	at := time.Unix(1_700_000_010, 0)
	for _, skew := range []uint{0, 1, 2} {
		k := &Key{Secret: rfcSHA1, SkewSteps: skew}
		for off := -3; off <= 3; off++ {
			code, _ := k.Code(at.Add(time.Duration(off) * 30 * time.Second))
			_, err := k.Verify(code, at, 0)
			inSkew := off >= -int(skew) && off <= int(skew)
			if (err == nil) != inSkew {
				t.Errorf("skew %d offset %d: %v", skew, off, err)
			}
			if !inSkew && !errors.Is(err, ErrCodeMismatch) {
				t.Errorf("skew %d offset %d: %v, want ErrCodeMismatch", skew, off, err)
			}
		}
	}
	// Skew at the ends of the counter range does not wrap.
	k := &Key{Secret: rfcSHA1, SkewSteps: 3}
	if n, err := k.Verify("755224", time.Unix(29, 0), 0); err != nil || n != 1 {
		t.Fatalf("Verify at step 0 = %d, %v", n, err)
	}
	k.SkewSteps, k.Kind = 2, HOTP
	code, _ := k.CounterCode(1<<64 - 2)
	if n, err := k.VerifyCounter(code, 1<<64-3); err != nil || n != 1<<64-1 {
		t.Fatalf("VerifyCounter at the end = %d, %v", n, err)
	}
	// The last counter is never accepted.
	last, _ := k.CounterCode(1<<64 - 1)
	for _, next := range []uint64{1<<64 - 2, 1<<64 - 1} {
		if _, err := k.VerifyCounter(last, next); !errors.Is(err, ErrCodeMismatch) {
			t.Fatalf("last counter from %d: %v", next, err)
		}
	}
	k.Kind = TOTP
	if _, err := k.Verify("000000", time.Unix(-1, 0), 0); !errors.Is(err, ErrInvalidTime) {
		t.Fatal(err)
	}
	if _, err := k.Code(time.Unix(-1, 0)); !errors.Is(err, ErrInvalidTime) {
		t.Fatal(err)
	}
}

func TestVerifyCounter(t *testing.T) {
	k := &Key{Secret: rfcSHA1, SkewSteps: 3, Kind: HOTP}
	// RFC 4226 counter 3 is 969429: accepted from next 0 with
	// look-ahead 3, and the token resynchronises to 4.
	n, err := k.VerifyCounter("969429", 0)
	if err != nil || n != 4 {
		t.Fatalf("VerifyCounter = %d, %v", n, err)
	}
	if _, err := k.VerifyCounter("969429", n); !errors.Is(err, ErrCodeMismatch) {
		t.Fatalf("reused HOTP code: %v", err)
	}
	if _, err := k.VerifyCounter("520489", 0); !errors.Is(err, ErrCodeMismatch) {
		t.Fatalf("beyond look-ahead: %v", err)
	}
}

func TestCodeFormat(t *testing.T) {
	k := &Key{Secret: rfcSHA1}
	at := time.Unix(59, 0)
	code, _ := k.Code(at)
	for _, c := range []string{"", "28708", "2870820", "+87082", "-87082", " 87082", "87082 ", "2870８2", "28708a", "0x1234"} {
		if _, err := k.Verify(c, at, 0); !errors.Is(err, ErrCodeFormat) {
			t.Errorf("Verify(%q) = %v", c, err)
		}
		if _, err := (&Key{Secret: rfcSHA1, Kind: HOTP}).VerifyCounter(c, 0); !errors.Is(err, ErrCodeFormat) {
			t.Errorf("VerifyCounter(%q) = %v", c, err)
		}
	}
	if _, err := k.Verify(code, at, 0); err != nil {
		t.Fatal(err)
	}
}

func TestKeyValidate(t *testing.T) {
	bad := []*Key{
		nil,
		{},
		{Secret: make([]byte, MinSecretSize-1)},
		{Secret: rfcSHA1, Digits: 5},
		{Secret: rfcSHA1, Digits: 11},
		{Secret: rfcSHA1, Period: 1500 * time.Millisecond},
		{Secret: rfcSHA1, Period: -time.Second},
		{Secret: rfcSHA1, Algorithm: Algorithm(3)},
	}
	for _, k := range bad {
		if err := k.Validate(); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("Validate(%+v) = %v", k, err)
		}
		if _, err := k.Verify("123456", time.Now(), 0); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("Verify with %+v = %v", k, err)
		}
		if _, err := k.VerifyCounter("123456", 0); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("VerifyCounter with %+v = %v", k, err)
		}
		if _, err := k.Code(time.Now()); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("Code with %+v = %v", k, err)
		}
		if _, err := k.CounterCode(0); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("CounterCode with %+v = %v", k, err)
		}
		if _, err := k.Step(time.Now()); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("Step with %+v = %v", k, err)
		}
		if _, err := k.URI(); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("URI with %+v = %v", k, err)
		}
	}
	k := &Key{Secret: rfcSHA1, Digits: 10, Period: time.Minute}
	if c, err := k.Code(time.Unix(59, 0)); err != nil || len(c) != 10 {
		t.Fatalf("10 digits: %q, %v", c, err)
	}
	if Algorithm(9).String() != "Algorithm(9)" || Kind(9).String() != "Kind(9)" {
		t.Fatal("String of unknown values")
	}
}

func TestShortSecret(t *testing.T) {
	k := &Key{Secret: rfcSHA1[:10]}
	if err := k.Validate(); !errors.Is(err, ErrInvalidKey) {
		t.Fatal("80-bit secret accepted by default")
	}
	k.AllowShortSecret = true
	if err := k.Validate(); err != nil {
		t.Fatal(err)
	}
	k.Secret = rfcSHA1[:9]
	if err := k.Validate(); !errors.Is(err, ErrInvalidKey) {
		t.Fatal("secret below the legacy minimum accepted")
	}
}

func TestGenerateSecret(t *testing.T) {
	s, err := GenerateSecret(DefaultSecretSize)
	if err != nil || len(s) != DefaultSecretSize {
		t.Fatal(s, err)
	}
	s2, _ := GenerateSecret(DefaultSecretSize)
	if bytes.Equal(s, s2) {
		t.Fatal("secrets repeat")
	}
	if _, err := GenerateSecret(MinSecretSize - 1); !errors.Is(err, ErrInvalidKey) {
		t.Fatal(err)
	}
}

func TestSecretEncoding(t *testing.T) {
	secret := rfcSHA1
	enc := EncodeSecret(secret)
	if enc != "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" {
		t.Fatal(enc)
	}
	good := map[string][]byte{
		enc:                  secret,
		strings.ToLower(enc): secret,
		"MFRGG":              []byte("abc"),
		"mfrgg===":           []byte("abc"),
		"MY======":           []byte("f"),
		"MZXQ====":           []byte("fo"),
		"MZXW6===":           []byte("foo"),
		"MZXW6YQ=":           []byte("foob"),
	}
	for in, want := range good {
		got, err := DecodeSecret(in)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("DecodeSecret(%q) = %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "MFRGG=", "MFRGG====", "MZXW6YQ==", "MFR GG", "MFRGG\n", "MFRG1", "MFRGG0", "M", "MFRGH", "========", "MY=====", "MFRGG===\r\n", "MZXW6YR="} {
		if _, err := DecodeSecret(in); !errors.Is(err, ErrInvalidSecret) {
			t.Errorf("DecodeSecret(%q) = %v", in, err)
		}
	}
}

func TestURIRoundTrip(t *testing.T) {
	keys := []*Key{
		{Issuer: "Example Co", Account: "alice@example.com", Secret: rfcSHA1},
		{Account: "bob", Secret: rfcSHA256, Algorithm: SHA256, Digits: 8, Period: time.Minute},
		{Issuer: "a:b/c?d&e=f g+h%", Account: "x:y/z", Secret: rfcSHA512, Algorithm: SHA512, Kind: HOTP, Counter: 42},
		{Issuer: "日本", Account: "ü", Secret: rfcSHA1, Kind: HOTP},
	}
	for _, k := range keys {
		uri, err := k.URI()
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseURI(uri)
		if err != nil {
			t.Fatalf("ParseURI(%q): %v", uri, err)
		}
		if got.Issuer != k.Issuer || got.Account != k.Account || !bytes.Equal(got.Secret, k.Secret) ||
			got.Algorithm != k.Algorithm || got.Digits != k.Digits || got.Period != k.Period ||
			got.Kind != k.Kind || got.Counter != k.Counter {
			t.Errorf("round trip of %+v via %q: %+v", k, uri, got)
		}
	}
	uri, _ := keys[0].URI()
	if uri != "otpauth://totp/Example%20Co:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example%20Co" {
		t.Fatal(uri)
	}
	if _, err := (&Key{Secret: rfcSHA1, Kind: Kind(5)}).URI(); !errors.Is(err, ErrInvalidKey) {
		t.Fatal(err)
	}
}

func TestParseURI(t *testing.T) {
	const s = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	good := map[string]Key{
		"otpauth://totp/ACME%20Co:john.doe@email.com?secret=" + s + "&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30": {Issuer: "ACME Co", Account: "john.doe@email.com", Digits: 6, Period: 30 * time.Second},
		"otpauth://TOTP/ACME%3A%20john?secret=" + strings.ToLower(s):                                                      {Issuer: "ACME", Account: "john"},
		"otpauth://totp/john?secret=" + s + "&issuer=ACME&image=https://example.com/x.png":                                {Issuer: "ACME", Account: "john"},
		"otpauth://hotp/x?secret=" + s + "&counter=7&algorithm=sha256":                                                    {Account: "x", Kind: HOTP, Counter: 7, Algorithm: SHA256},
		"otpauth://totp/?secret=" + s:                  {},
		"otpauth://totp/a:b?secret=" + s + "&issuer=a": {Issuer: "a", Account: "b"},
	}
	for uri, want := range good {
		got, err := ParseURI(uri)
		if err != nil {
			t.Errorf("ParseURI(%q): %v", uri, err)
			continue
		}
		want.Secret = rfcSHA1
		if got.Issuer != want.Issuer || got.Account != want.Account || got.Kind != want.Kind ||
			got.Counter != want.Counter || got.Algorithm != want.Algorithm || got.Digits != want.Digits ||
			got.Period != want.Period || !bytes.Equal(got.Secret, want.Secret) {
			t.Errorf("ParseURI(%q) = %+v, want %+v", uri, got, want)
		}
	}
	bad := []string{
		"",
		"http://totp/x?secret=" + s,
		"otpauth:totp/x?secret=" + s,
		"otpauth://user@totp/x?secret=" + s,
		"otpauth://totp/x?secret=" + s + "#frag",
		"otpauth://motp/x?secret=" + s,
		"otpauth://totp/x",
		"otpauth://totp/x?secret=",
		"otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ",
		"otpauth://totp/x?secret=" + s + "&secret=" + s,
		"otpauth://totp/x?secret=" + s + "&algorithm=MD5",
		"otpauth://totp/x?secret=" + s + "&digits=5",
		"otpauth://totp/x?secret=" + s + "&digits=+6",
		"otpauth://totp/x?secret=" + s + "&digits=11",
		"otpauth://totp/x?secret=" + s + "&period=0",
		"otpauth://totp/x?secret=" + s + "&period=-30",
		"otpauth://totp/x?secret=" + s + "&period=99999999999999999999",
		"otpauth://totp/x?secret=" + s + "&period=9223372037",
		"otpauth://hotp/x?secret=" + s,
		"otpauth://hotp/x?secret=" + s + "&counter=1e3",
		"otpauth://totp/a:b?secret=" + s + "&issuer=c",
		"otpauth://totp/a/b?secret=" + s,
		"otpauth://totp/a%zz?secret=" + s,
		"otpauth://totp/x?secret=" + s + "&issuer=a&issuer=b",
		"otpauth://totp/x?secret=" + s + ";x=y",
		"otpauth://totp/x?secret=" + s + "&digits=6&digits=6",
		"otpauth://totp/x?secret=" + s + "&period=30&period=30",
		"otpauth://hotp/x?secret=" + s + "&counter=1&counter=2",
		"otpauth://totp/x?secret=" + s + "&algorithm=SHA1&algorithm=SHA1",
	}
	for _, uri := range bad {
		if k, err := ParseURI(uri); err == nil {
			t.Errorf("ParseURI(%q) = %+v", uri, k)
		}
	}
}

func FuzzDecodeSecret(f *testing.F) {
	for _, s := range []string{"GEZDGNBVGY3TQOJQ", "mfrgg===", "MY======", "", "=", "MFRGH"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		b, err := DecodeSecret(s)
		if err != nil {
			if !errors.Is(err, ErrInvalidSecret) {
				t.Fatal(err)
			}
			return
		}
		norm := strings.ToUpper(strings.TrimRight(s, "="))
		if EncodeSecret(b) != norm {
			t.Fatalf("DecodeSecret(%q) = %x, which encodes to %q", s, b, EncodeSecret(b))
		}
	})
}

func FuzzParseURI(f *testing.F) {
	k := &Key{Issuer: "a:b", Account: "c d", Secret: rfcSHA1, Kind: HOTP, Counter: 3, Digits: 8}
	uri, _ := k.URI()
	f.Add(uri)
	f.Add("otpauth://totp/ACME:john?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=60&algorithm=SHA512")
	f.Add("otpauth://totp/%3A?secret=")
	f.Fuzz(func(t *testing.T, s string) {
		k, err := ParseURI(s)
		if err != nil {
			return
		}
		if err := k.Validate(); err != nil {
			t.Fatalf("ParseURI(%q) returned an invalid key: %v", s, err)
		}
		uri, err := k.URI()
		if err != nil {
			t.Fatal(err)
		}
		k2, err := ParseURI(uri)
		if err != nil {
			t.Fatalf("ParseURI(%q) -> URI %q: %v", s, uri, err)
		}
		if k2.Issuer != k.Issuer || k2.Account != k.Account || !bytes.Equal(k2.Secret, k.Secret) ||
			k2.Kind != k.Kind || k2.Counter != k.Counter || k2.Algorithm != k.Algorithm {
			t.Fatalf("round trip %q -> %q: %+v != %+v", s, uri, k2, k)
		}
	})
}

func FuzzVerify(f *testing.F) {
	f.Add("287082", uint64(0))
	f.Add("+87082", uint64(1))
	k := &Key{Secret: rfcSHA1, SkewSteps: 1}
	f.Fuzz(func(t *testing.T, code string, next uint64) {
		n, err := k.Verify(code, time.Unix(59, 0), next)
		if err == nil && (n <= next || !wellFormed(code, 6)) {
			t.Fatalf("Verify(%q, %d) = %d", code, next, n)
		}
	})
}

func BenchmarkVerify(b *testing.B) {
	k := &Key{Secret: rfcSHA1, SkewSteps: 1}
	at := time.Unix(1_700_000_000, 0)
	code, _ := k.Code(at)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := k.Verify(code, at, 0); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCode(b *testing.B) {
	k := &Key{Secret: rfcSHA1}
	at := time.Unix(1_700_000_000, 0)
	b.ReportAllocs()
	for b.Loop() {
		_, _ = k.Code(at)
	}
}

// TestGeneratorMatchesHMAC checks the stack HMAC against crypto/hmac,
// including secrets longer than the hash's block size.
func TestGeneratorMatchesHMAC(t *testing.T) {
	news := map[Algorithm]func() hash.Hash{SHA1: sha1.New, SHA256: sha256.New, SHA512: sha512.New}
	for alg, newHash := range news {
		for _, size := range []int{16, 20, 63, 64, 65, 127, 128, 129, 300} {
			secret := bytes.Repeat([]byte{byte(size), 0xa5}, size)[:size]
			k := &Key{Secret: secret, Algorithm: alg, Digits: 8, Kind: HOTP}
			for _, c := range []uint64{0, 1, 1 << 40} {
				m := hmac.New(newHash, secret)
				m.Write(binary.BigEndian.AppendUint64(nil, c))
				sum := m.Sum(nil)
				off := sum[len(sum)-1] & 0x0f
				want := fmt.Sprintf("%08d", (binary.BigEndian.Uint32(sum[off:])&0x7fffffff)%100_000_000)
				if got, err := k.CounterCode(c); err != nil || got != want {
					t.Errorf("%v secret %d counter %d: %q, %v, want %q", alg, size, c, got, err, want)
				}
			}
		}
	}
}

// TestStepAhead is a regression test: a stored step beyond the clock's
// window is reported as such, not as an ordinary reuse.
func TestStepAhead(t *testing.T) {
	k := &Key{Secret: rfcSHA1, SkewSteps: 1}
	at := time.Unix(1_700_000_000, 0)
	cur, _ := k.Step(at)
	code, _ := k.Code(at)
	// A login at the top of the window leaves next at cur+2: ordinary.
	if _, err := k.Verify(code, at, cur+2); !errors.Is(err, ErrCodeReused) {
		t.Fatalf("next at the window's end: %v", err)
	}
	if _, err := k.Verify(code, at, cur+3); !errors.Is(err, ErrStepAhead) {
		t.Fatalf("next beyond the window: %v", err)
	}
	// A wrong code reveals nothing about the stored step.
	wrong := "000000"
	if wrong == code {
		wrong = "000001"
	}
	if _, err := k.Verify(wrong, at, cur+100); !errors.Is(err, ErrCodeMismatch) {
		t.Fatalf("wrong code with next ahead: %v", err)
	}
	// After recovery, the code is accepted once more.
	if next, err := k.Verify(code, at, cur); err != nil || next != cur+1 {
		t.Fatalf("after reset: %d, %v", next, err)
	}
}

func TestVerifyAllocs(t *testing.T) {
	k := &Key{Secret: rfcSHA1, Algorithm: SHA512, SkewSteps: 2}
	at := time.Unix(1_700_000_000, 0)
	code, _ := k.Code(at)
	hk := *k
	hk.Kind = HOTP
	if n := testing.AllocsPerRun(100, func() {
		if _, err := k.Verify(code, at, 0); err != nil {
			t.Fatal(err)
		}
		if _, err := k.VerifyCounter(code, 0); !errors.Is(err, ErrInvalidKey) {
			t.Fatal("TOTP key verified a counter")
		}
		if _, err := hk.VerifyCounter(code, 0); err == nil {
			t.Fatal("counter code accepted")
		}
	}); n != 0 {
		t.Fatalf("Verify allocates %v times", n)
	}
}

func TestParseAlgorithm(t *testing.T) {
	for _, a := range []Algorithm{SHA1, SHA256, SHA512} {
		if b, err := ParseAlgorithm(strings.ToLower(a.String())); err != nil || b != a {
			t.Errorf("ParseAlgorithm(%v) = %v, %v", a, b, err)
		}
	}
	if _, err := ParseAlgorithm("MD5"); !errors.Is(err, ErrInvalidKey) {
		t.Error(err)
	}
}

// TestKindEnforced checks that a key is used only with the methods of its
// kind.
func TestKindEnforced(t *testing.T) {
	totp := &Key{Secret: rfcSHA1}
	hotp := &Key{Secret: rfcSHA1, Kind: HOTP}
	at := time.Unix(59, 0)
	code, _ := totp.Code(at)
	if _, err := hotp.Verify(code, at, 0); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("HOTP key Verify: %v", err)
	}
	if _, err := hotp.Code(at); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("HOTP key Code: %v", err)
	}
	if _, err := hotp.Step(at); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("HOTP key Step: %v", err)
	}
	if _, err := totp.VerifyCounter("755224", 0); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("TOTP key VerifyCounter: %v", err)
	}
	if _, err := totp.CounterCode(0); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("TOTP key CounterCode: %v", err)
	}
	if err := (&Key{Secret: rfcSHA1, Kind: Kind(7)}).Validate(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("unknown kind validates: %v", err)
	}
}

func TestKeyJSON(t *testing.T) {
	k := Key{Issuer: "Example", Account: "alice", Secret: rfcSHA256, Period: time.Minute, Digits: 8,
		SkewSteps: 1, Counter: 9, Algorithm: SHA256, Kind: HOTP}
	b, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	var got Key
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("%s: %v", b, err)
	}
	if !bytes.Equal(got.Secret, k.Secret) || got.Issuer != k.Issuer || got.Account != k.Account || got.Period != k.Period ||
		got.Digits != k.Digits || got.SkewSteps != k.SkewSteps || got.Counter != k.Counter ||
		got.Algorithm != k.Algorithm || got.Kind != k.Kind {
		t.Fatalf("round trip: %s -> %+v", b, got)
	}
	for _, bad := range []string{
		`{"secret": "` + EncodeSecret(rfcSHA1) + `", "Kind": "hotp"}`,
		`{"secret": "` + EncodeSecret(rfcSHA1) + `", "kind": "hotp", "kind": "totp"}`,
		`{"secret": "` + EncodeSecret(rfcSHA1) + `", "algorithm": 1}`,
		`{"secret": "` + EncodeSecret(rfcSHA1) + `", "period": 30}`,
		`{"secret": "short"}`,
		`{"secret": "` + EncodeSecret(rfcSHA1) + `", "kind": null}`,
	} {
		var k Key
		if err := json.Unmarshal([]byte(bad), &k); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if _, err := json.Marshal(Key{}); err == nil {
		t.Error("invalid key marshalled")
	}
}
