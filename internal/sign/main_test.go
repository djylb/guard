package sign

import (
	"testing"

	"github.com/djylb/guard/internal/leakcheck"
)

func TestMain(m *testing.M) { leakcheck.VerifyTestMain(m) }
