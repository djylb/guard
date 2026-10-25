//go:build race

package webguard

// raceEnabled reports a race build, where sync.Pool drops items at random.
const raceEnabled = true
