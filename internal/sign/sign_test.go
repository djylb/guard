package sign

import (
	"bytes"
	"testing"

	"github.com/djylb/guard/internal/race"
)

var (
	key1 = bytes.Repeat([]byte{1}, 16)
	key2 = bytes.Repeat([]byte{2}, 16)
)

func TestSignVerify(t *testing.T) {
	s, err := New("test", key2, [][]byte{key1}, 16)
	if err != nil {
		t.Fatal(err)
	}
	old, err := New("test", key1, nil, 16)
	if err != nil {
		t.Fatal(err)
	}
	header := []byte("header")
	tag := old.Sign(header, "a", "b")
	if !s.Verify(tag[:], header, "a", "b") {
		t.Fatal("previous key does not verify")
	}
	for _, f := range [][]string{{"ab"}, {"a", "b", ""}, {"b", "a"}} {
		if s.Verify(tag[:], header, f...) {
			t.Errorf("fields %q verify", f)
		}
	}
	if s.Verify(tag[:Size-1], header, "a", "b") {
		t.Error("short tag verifies")
	}
	if tag2 := s.Sign(header, "a", "b"); tag2 == tag || old.Verify(tag2[:], header, "a", "b") || !s.Verify(tag2[:], header, "a", "b") {
		t.Error("signs with a previous key, or does not verify its own tag")
	}
	other, _ := New("other", key1, nil, 16)
	if other.Verify(tag[:], header, "a", "b") {
		t.Error("domains not separated")
	}
}

func TestNew(t *testing.T) {
	for _, tt := range []struct {
		key  []byte
		prev [][]byte
	}{
		{nil, [][]byte{key1}},
		{key1[:15], nil},
		{make([]byte, 16), nil},
		{key1, [][]byte{make([]byte, 16)}},
	} {
		if _, err := New("d", tt.key, tt.prev, 16); err == nil {
			t.Errorf("New(%x, %x) accepted", tt.key, tt.prev)
		}
	}
	a, _ := New("d", nil, nil, 16)
	b, _ := New("d", nil, nil, 16)
	if tag := a.Sign(nil); b.Verify(tag[:], nil) {
		t.Error("random keys equal")
	}
	k := bytes.Clone(key1)
	c, _ := New("d", k, nil, 16)
	tag := c.Sign(nil, "x")
	k[0] ^= 1
	if !c.Verify(tag[:], nil, "x") {
		t.Error("key not copied")
	}
}

func TestSealOpen(t *testing.T) {
	s, _ := New("d", key1, nil, 16)
	var raw [4 + NonceSize + Size]byte
	copy(raw[:], "head")
	tok := s.Seal(raw[:], "f")
	if len(tok) != TokenLen(len(raw)) {
		t.Fatalf("token length %d", len(tok))
	}
	var got [len(raw)]byte
	if !Open(got[:], tok) || got != raw || !s.Check(got[:], "f") || s.Check(got[:], "g") {
		t.Fatal("round trip failed")
	}
	if Open(got[:], tok[1:]) || Open(got[:], tok+"A") || Open(make([]byte, MaxRaw+1), tok) {
		t.Error("wrong length opened")
	}
	// The last character carries unused bits: another spelling is rejected.
	alt := []byte(tok)
	alt[len(alt)-1] ^= 1
	if Open(got[:], string(alt)) {
		t.Error("non-canonical spelling opened")
	}
	if race.Enabled() {
		return // sync.Pool drops items at random
	}
	if n := testing.AllocsPerRun(100, func() { _ = Open(got[:], tok) && s.Check(got[:], "f") }); n != 0 {
		t.Errorf("Open and Check allocate %v times", n)
	}
}
