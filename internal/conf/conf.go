// Package conf decodes and encodes the JSON form of the guard packages'
// configs and the text form of their enums.
package conf

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"
)

// Duration is a time.Duration written in JSON as a string that
// time.ParseDuration accepts, such as "90s" or "1h30m". Numbers are
// rejected, so that 30 cannot silently mean 30 nanoseconds.
type Duration time.Duration

// UnmarshalJSON implements json.Unmarshaler.
//
//goland:noinspection GoMixedReceiverTypes
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errors.New(`duration is not a string such as "30s"`)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return errors.New(`duration is not in time.ParseDuration form, such as "1m30s"`)
	}
	*d = Duration(v)
	return nil
}

// MarshalJSON implements json.Marshaler, writing the String form.
//
//goland:noinspection GoMixedReceiverTypes
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// Decode decodes the JSON object in data, which json.Unmarshal has
// checked to be a single value, into v, a pointer to a struct whose
// fields carry json tags. Each name in data must equal a tag exactly and
// appear once, so that a misspelt, differently cased or repeated setting
// is an error rather than a silent default or a silent override, and no
// value may be null, which would otherwise keep some fields and fail
// others.
func Decode(data []byte, v any) error {
	names := tags(v)
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil {
		return err
	} else if tok != json.Delim('{') {
		return errors.New("config is not an object")
	}
	seen := make(map[string]bool, len(names))
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		name, _ := tok.(string)
		if !slices.Contains(names, name) {
			return fmt.Errorf("unknown field %q", name)
		}
		if seen[name] {
			return fmt.Errorf("field %q repeated", name)
		}
		seen[name] = true
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return err
		}
		if string(raw) == "null" {
			return fmt.Errorf("field %q is null", name)
		}
	}
	dec = json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// tags returns the json names of the fields of the struct v points to.
func tags(v any) []string {
	t := reflect.TypeOf(v).Elem()
	names := make([]string, 0, t.NumField())
	for i := range t.NumField() {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if name != "" && name != "-" {
			names = append(names, name)
		}
	}
	return names
}

// Key is a secret key in JSON: standard base64, or the string "random"
// for a key generated per process, which must be asked for explicitly.
type Key struct {
	Bytes  []byte
	Set    bool // the field was present
	Random bool
}

// UnmarshalJSON implements json.Unmarshaler.
//
//goland:noinspection GoMixedReceiverTypes
func (k *Key) UnmarshalJSON(b []byte) error {
	k.Set = true
	if string(b) == `"random"` {
		k.Bytes, k.Random = nil, true
		return nil
	}
	if err := json.Unmarshal(b, &k.Bytes); err != nil || len(k.Bytes) == 0 {
		return errors.New(`key is neither standard base64 nor "random"`)
	}
	return nil
}

// Resolve returns the key to use: the decoded one, the previous one if
// the field was absent, or nil for "random". A key that is neither given
// now nor before is an error, so that a config file without a key does
// not silently get a key valid only in this process.
//
//goland:noinspection GoMixedReceiverTypes
func (k *Key) Resolve(previous []byte) ([]byte, error) {
	switch {
	case k.Random:
		return nil, nil
	case k.Set:
		return k.Bytes, nil
	case previous != nil:
		return previous, nil
	default:
		return nil, errors.New(`no key: give one in base64, or "random" for a key valid only in this process`)
	}
}

// Redacted returns the form of key in a marshalled Config, which writes
// no secret: "random" for a nil key, which asks for a key generated per
// process, and the zero Key for a given key, which a field tagged
// omitzero leaves out.
func Redacted(key []byte) Key {
	return Key{Random: key == nil}
}

// IsZero reports whether k is not "random", for omitzero.
//
//goland:noinspection GoMixedReceiverTypes
func (k Key) IsZero() bool {
	return !k.Random
}

// MarshalJSON implements json.Marshaler. It writes "random" and never a
// key's bytes: a given key is an error, so that a field without
// omitzero cannot leak it.
//
//goland:noinspection GoMixedReceiverTypes
func (k Key) MarshalJSON() ([]byte, error) {
	if !k.Random {
		return nil, errors.New("a key is not written")
	}
	return []byte(`"random"`), nil
}

// ParseName returns the index of the name in names that equals s,
// ignoring case, for the String forms of the guard packages' enums.
func ParseName(s string, names ...string) (int, bool) {
	for i, n := range names {
		if strings.EqualFold(s, n) {
			return i, true
		}
	}
	return 0, false
}
