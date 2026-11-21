package num

import "testing"

func TestShards(t *testing.T) {
	for _, tt := range []struct{ n, capacity, procs, want int }{
		{0, 64, 16, 1},       // small tables get one shard
		{0, 4096, 64, 16},    // at least MinShardSize per shard
		{0, 1 << 16, 15, 32}, // 4*15 = 60, lowered to a power of two
		{0, 1 << 20, 2, 8},   // a multiple of procs
		{3, 64, 16, 4},       // explicit: rounded up
		{16, 4, 1, 4},        // explicit: at least one entry per shard
		{0, 0, 1, 1},
	} {
		if got := Shards(tt.n, tt.capacity, tt.procs); got != tt.want {
			t.Errorf("Shards(%d, %d, %d) = %d, want %d", tt.n, tt.capacity, tt.procs, got, tt.want)
		}
	}
}

func TestSaturating(t *testing.T) {
	const maxI, minI = int64(1<<63 - 1), int64(-1 << 63)
	for _, tt := range []struct{ a, b, add int64 }{
		{1, 2, 3},
		{maxI, 1, maxI},
		{minI, -1, minI},
		{maxI, -1, maxI - 1},
		{minI, 1, minI + 1},
		{maxI, minI, -1},
		{5, maxI, maxI},
	} {
		if got := SatAdd(tt.a, tt.b); got != tt.add {
			t.Errorf("SatAdd(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.add)
		}
	}
	for _, tt := range []struct{ a, b, want int64 }{
		{0, maxI, 0},
		{3, 4, 12},
		{1 << 31, 1 << 31, 1 << 62},
		{1 << 32, 1 << 31, maxI},
		{maxI, 2, maxI},
		{maxI, 1, maxI},
	} {
		if got := SatMul(tt.a, tt.b); got != tt.want {
			t.Errorf("SatMul(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}
