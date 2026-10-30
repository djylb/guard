// Package race reports whether the running binary was built with the race
// detector, for tests whose allocation counts it changes.
package race

import (
	"runtime/debug"
	"sync"
)

// Enabled reports whether the binary was built with -race, where
// sync.Pool drops items at random.
var Enabled = sync.OnceValue(func() bool {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return false
	}
	for _, s := range bi.Settings {
		if s.Key == "-race" {
			return s.Value == "true"
		}
	}
	return false
})
