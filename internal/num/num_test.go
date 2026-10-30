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
