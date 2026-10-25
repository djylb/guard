package sign

import (
	"bytes"
	"testing"
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
