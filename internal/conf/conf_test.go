package conf

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type sample struct {
	Window Duration `json:"window"`
	Count  int      `json:"count"`
}

func TestDecode(t *testing.T) {
	var v sample
	if err := Decode([]byte(`{"window": "1m", "count": 3}`), &v); err != nil || v.Window != Duration(time.Minute) || v.Count != 3 {
		t.Fatalf("Decode = %+v, %v", v, err)
	}
	for _, bad := range []string{
		`{"WINDOW": "1m"}`,         // case differs
		`{"count": 1, "count": 2}`, // repeated
		`{"count": null}`,          // null
		`{"other": 1}`,             // unknown
		`{"window": 30}`,           // number duration
		`null`, `[]`, `"x"`,
	} {
		if err := Decode([]byte(bad), &sample{}); err == nil {
			t.Errorf("Decode(%s) accepted", bad)
		}
	}
	b, err := json.Marshal(sample{Window: Duration(90 * time.Second)})
	if err != nil || string(b) != `{"window":"1m30s","count":0}` {
		t.Fatalf("Marshal = %s, %v", b, err)
	}
}

// TestDecodeNoEcho is a regression test: a config that is not an object,
// such as a key given where the object belongs, must not appear in the
// error, which may be logged.
func TestDecodeNoEcho(t *testing.T) {
	var v sample
	for _, in := range []string{`"c2VjcmV0LWtleQ=="`, `["c2VjcmV0LWtleQ=="]`, `12345678`, `{"window":"c2VjcmV0LWtleQ=="}`, `{"window":12345678}`} {
		err := Decode([]byte(in), &v)
		if err == nil || strings.Contains(err.Error(), "c2VjcmV0") || strings.Contains(err.Error(), "12345678") {
			t.Errorf("Decode(%s) = %v", in, err)
		}
	}
}

func TestKeyMarshal(t *testing.T) {
	if b, err := json.Marshal(Redacted(nil)); err != nil || string(b) != `"random"` {
		t.Errorf("random key: %s, %v", b, err)
	}
	if _, err := json.Marshal(Key{Bytes: []byte("secret"), Set: true}); err == nil {
		t.Error("a given key was written")
	}
	if !Redacted([]byte("secret")).IsZero() {
		t.Error("a given key is not left out")
	}
}
