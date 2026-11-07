package otp_test

import (
	"testing"

	"github.com/djylb/guard/internal/leakcheck"
)

func TestMain(m *testing.M) { leakcheck.VerifyTestMain(m) }
