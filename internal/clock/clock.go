// Package clock measures time for the guard packages' tables: durations
// on the monotonic clock, from a base taken at construction, and wall
// times relative to the same base.
package clock

import "time"

// Clock reads a time source and expresses its readings as nanoseconds
// since the Clock was created. Its zero value is not usable.
type Clock struct {
	now  func() time.Time
	base time.Time // the first reading, with its monotonic reading
	wall time.Time // base without its monotonic reading
}

// New returns a Clock that reads now, or time.Now if now is nil. A source
// without monotonic readings makes Mono follow its wall time.
func New(now func() time.Time) Clock {
	if now == nil {
		now = time.Now
	}
	base := now()
	return Clock{now: now, base: base, wall: base.Round(0)}
}

// Read returns the current time and its monotonic offset from the base
// in nanoseconds.
func (c *Clock) Read() (time.Time, int64) {
	t := c.now()
	return t, int64(t.Sub(c.base))
}

// Mono returns the monotonic nanoseconds since the base.
func (c *Clock) Mono() int64 {
	_, m := c.Read()
	return m
}

// Wall returns the wall nanoseconds of t since the base, ignoring any
// monotonic reading, saturated at the int64 range.
func (c *Clock) Wall(t time.Time) int64 {
	return int64(t.Round(0).Sub(c.wall))
}

// At returns the wall time of an offset in nanoseconds since the base.
func (c *Clock) At(off int64) time.Time {
	return c.wall.Add(time.Duration(off))
}
