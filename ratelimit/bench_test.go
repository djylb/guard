package ratelimit

import (
	"strconv"
	"sync/atomic"
	"testing"
)

var benchRate = Rate{Per: 1e6, Burst: 1 << 20}

func BenchmarkAllowSingleKey(b *testing.B) {
	l := mustNew(b, Config{})
	now := l.origin
	b.ReportAllocs()
	for b.Loop() {
		l.Allow("203.0.113.7", benchRate, 1, now)
	}
}

func BenchmarkAllowRefused(b *testing.B) {
	l := mustNew(b, Config{})
	now := l.origin
	r := Rate{Per: 1, Burst: 1}
	l.Allow("k", r, 1, now)
	b.ReportAllocs()
	for b.Loop() {
		l.Allow("k", r, 1, now)
	}
}

func BenchmarkAllowParallelSingleKey(b *testing.B) {
	l := mustNew(b, Config{})
	now := l.origin
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			l.Allow("203.0.113.7", benchRate, 1, now)
		}
	})
}

func benchKeys(n int) []string {
	keys := make([]string, n)
	for i := range keys {
		keys[i] = "203.0.113." + strconv.Itoa(i)
	}
	return keys
}

func BenchmarkAllowParallelManyKeys(b *testing.B) {
	l := mustNew(b, Config{})
	now := l.origin
	keys := benchKeys(1 << 14)
	var next atomic.Uint32
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := int(next.Add(1)) * 977
		for pb.Next() {
			i++
			l.Allow(keys[i%len(keys)], benchRate, 1, now)
		}
	})
}

// BenchmarkAllowEvicting runs more keys than the table holds, so that every
// call replaces the least recently used key.
func BenchmarkAllowEvicting(b *testing.B) {
	l := mustNew(b, Config{Capacity: 1024})
	now := l.origin
	keys := benchKeys(1 << 14)
	i := 0
	b.ReportAllocs()
	for b.Loop() {
		i++
		l.Allow(keys[i%len(keys)], benchRate, 1, now)
	}
}

func BenchmarkGCRA(b *testing.B) {
	var g GCRA
	b.ReportAllocs()
	now := int64(0)
	for b.Loop() {
		now += 1000
		g.Allow(now, benchRate, 1)
	}
}
