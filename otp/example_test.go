package otp_test

import (
	"fmt"
	"time"

	"github.com/djylb/guard/otp"
)

func Example() {
	secret, err := otp.GenerateSecret(otp.DefaultSecretSize)
	if err != nil {
		panic(err)
	}
	key := &otp.Key{Issuer: "Example", Account: "alice", Secret: secret, SkewSteps: 1}
	uri, err := key.URI() // show as a QR code during enrolment
	if err != nil {
		panic(err)
	}
	_ = uri

	// At login, with the account's stored next step (0 when new).
	var nextStep uint64
	now := time.Now()
	code, _ := key.Code(now) // what the user's app shows
	nextStep, err = key.Verify(code, now, nextStep)
	fmt.Println(err)
	// Store nextStep. The same code is refused from now on.
	_, err = key.Verify(code, now, nextStep)
	fmt.Println(err)
	// Output:
	// <nil>
	// otp: code already used
}

func ExampleParseURI() {
	key, err := otp.ParseURI("otpauth://totp/Example:alice?secret=gezdgnbvgy3tqojqgezdgnbvgy3tqojq&issuer=Example")
	if err != nil {
		panic(err)
	}
	code, _ := key.Code(time.Unix(59, 0))
	fmt.Println(key.Issuer, key.Account, code)
	// Output: Example alice 287082
}
