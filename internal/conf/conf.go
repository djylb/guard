// Package conf decodes the JSON form of the guard packages' configs.
package conf

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Duration is a time.Duration written in JSON as a string that
// time.ParseDuration accepts, such as "90s" or "1h30m". Numbers are
// rejected, so that 30 cannot silently mean 30 nanoseconds.
type Duration time.Duration

// UnmarshalJSON implements json.Unmarshaler.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration %s is not a string such as \"30s\"", b)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// Enum decodes a JSON string with parse, for the policy and algorithm
// types of the guard packages.
type Enum[T any] struct {
	Parse func(string) (T, error)
	Value T
}

// UnmarshalJSON implements json.Unmarshaler.
func (e *Enum[T]) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("%s is not a string", b)
	}
	v, err := e.Parse(s)
	if err != nil {
		return err
	}
	e.Value = v
	return nil
}

// Decode decodes the JSON object in data, which json.Unmarshal has
// checked to be a single value, into v. It rejects unknown fields, so that
// a misspelt setting is an error rather than a silent default, and null
// values, which would otherwise keep some fields and fail others.
func Decode(data []byte, v any) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if fields == nil {
		return errors.New("config is null")
	}
	for name, raw := range fields {
		if string(raw) == "null" {
			return fmt.Errorf("field %q is null", name)
		}
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// Key is a secret key in JSON: standard base64, or the string "random"
// for a key generated per process, which must be asked for explicitly.
type Key struct {
	Bytes  []byte
	Set    bool // the field was present
	Random bool
}

// UnmarshalJSON implements json.Unmarshaler.
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
