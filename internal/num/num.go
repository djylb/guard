// Package num holds the integer helpers that several guard packages share.
package num

import (
	"math"
	"math/bits"
)

// SatAdd returns a+b, saturated at the int64 range.
func SatAdd(a, b int64) int64 {
	if b > 0 && a > math.MaxInt64-b {
		return math.MaxInt64
	}
	if b < 0 && a < math.MinInt64-b {
		return math.MinInt64
	}
	return a + b
}

// CeilPow2 returns the smallest power of two that is at least n, and 1
// for n below 1.
func CeilPow2(n int) int {
	if n <= 1 {
		return 1
	}
	return 1 << bits.Len(uint(n-1))
}

// MinShardSize is the number of entries per shard below which a default
// shard count is lowered: full-table policies act per shard, so small
// shards would make a table behave as full long before it holds its
// capacity.
const MinShardSize = 256

// Shards returns the shard count for a table of capacity entries. An
// explicit n is rounded up to a power of two and lowered so that each
// shard holds at least one entry. When n is zero, it is a multiple of
// procs, lowered to a power of two such that each shard holds at least
// MinShardSize entries, and at least 1.
func Shards(n, capacity, procs int) int {
	if n == 0 {
		n = min(4*procs, max(1, capacity/MinShardSize))
		return 1 << (bits.Len(uint(n)) - 1)
	}
	n = CeilPow2(min(n, capacity))
	for n > 1 && n > capacity {
		n >>= 1
	}
	return n
}
