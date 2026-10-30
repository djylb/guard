package otp

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/djylb/guard/internal/conf"
)

// jsonKey is the JSON form of a Key.
type jsonKey struct {
	Issuer           string        `json:"issuer"`
	Account          string        `json:"account"`
	Secret           string        `json:"secret"`
	Period           conf.Duration `json:"period"`
	Digits           int           `json:"digits"`
	SkewSteps        uint          `json:"skew_steps"`
	Counter          uint64        `json:"counter"`
	Algorithm        Algorithm     `json:"algorithm"`
	AllowShortSecret bool          `json:"allow_short_secret"`
	Kind             Kind          `json:"kind"`
}

// MarshalJSON writes k as a JSON object, for storing it with its account:
//
//	{"issuer": "Example", "account": "alice", "secret": "JBSWY3DPEHPK3PXP...",
//	 "period": "30s", "digits": 6, "skew_steps": 1, "counter": 0,
//	 "algorithm": "SHA1", "allow_short_secret": false, "kind": "totp"}
//
// The secret is written in base32, as EncodeSecret does: keep the result
// as secret as the Key. It fails for a Key that Validate rejects.
//
//goland:noinspection GoMixedReceiverTypes
func (k Key) MarshalJSON() ([]byte, error) {
	if err := k.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(jsonKey{
		Issuer: k.Issuer, Account: k.Account, Secret: EncodeSecret(k.Secret),
		Period: conf.Duration(k.Period), Digits: k.Digits, SkewSteps: k.SkewSteps,
		Counter: k.Counter, Algorithm: k.Algorithm, AllowShortSecret: k.AllowShortSecret, Kind: k.Kind,
	})
}

// UnmarshalJSON reads a Key in the form MarshalJSON writes. Fields that
// are absent keep their value; unknown, repeated and null fields are an
// error, and names must match exactly. The secret is decoded with
// DecodeSecret, and the result must pass Validate.
//
//goland:noinspection GoMixedReceiverTypes
func (k *Key) UnmarshalJSON(data []byte) error {
	v := jsonKey{
		Issuer: k.Issuer, Account: k.Account, Period: conf.Duration(k.Period), Digits: k.Digits,
		SkewSteps: k.SkewSteps, Counter: k.Counter, Algorithm: k.Algorithm,
		AllowShortSecret: k.AllowShortSecret, Kind: k.Kind,
	}
	if k.Secret != nil {
		v.Secret = EncodeSecret(k.Secret)
	}
	if err := conf.Decode(data, &v); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	secret, err := DecodeSecret(v.Secret)
	if err != nil {
		return err
	}
	nk := Key{
		Issuer: v.Issuer, Account: v.Account, Secret: secret, Period: time.Duration(v.Period),
		Digits: v.Digits, SkewSteps: v.SkewSteps, Counter: v.Counter, Algorithm: v.Algorithm,
		AllowShortSecret: v.AllowShortSecret, Kind: v.Kind,
	}
	if err := nk.Validate(); err != nil {
		return err
	}
	*k = nk
	return nil
}
