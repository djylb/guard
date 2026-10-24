//go:build race

package pow

// raceEnabled reports a race build, where sync.Pool drops items at random.
const raceEnabled = true
