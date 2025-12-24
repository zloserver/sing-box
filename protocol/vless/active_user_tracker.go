package vless

import (
	"hash/fnv"
	"sync"
	"time"
)

const (
	numBuckets = 5
	numShards  = 64
)

type shard struct {
	mu      sync.RWMutex
	buckets [numBuckets]map[string]struct{}
}

type ActiveUserTracker struct {
	shards     [numShards]*shard
	currentIdx int
	muIdx      sync.RWMutex
}

func NewActiveUserTracker() *ActiveUserTracker {
	tracker := &ActiveUserTracker{}
	for i := 0; i < numShards; i++ {
		tracker.shards[i] = &shard{}
		for j := 0; j < numBuckets; j++ {
			tracker.shards[i].buckets[j] = make(map[string]struct{})
		}
	}

	go tracker.rotateLoop()
	return tracker
}

func (t *ActiveUserTracker) getShard(userID string) *shard {
	h := fnv.New32a()
	h.Write([]byte(userID))
	return t.shards[uint32(h.Sum32())%numShards]
}

func (t *ActiveUserTracker) rotateLoop() {
	ticker := time.NewTicker(time.Minute)
	for range ticker.C {
		t.muIdx.Lock()
		newIdx := (t.currentIdx + 1) % numBuckets

		for i := 0; i < numShards; i++ {
			t.shards[i].mu.Lock()
			t.shards[i].buckets[newIdx] = make(map[string]struct{})
			t.shards[i].mu.Unlock()
		}

		t.currentIdx = newIdx
		t.muIdx.Unlock()
	}
}

func (t *ActiveUserTracker) RecordRequest(userID string) {
	shard := t.getShard(userID)

	t.muIdx.RLock()
	idx := t.currentIdx
	t.muIdx.RUnlock()

	shard.mu.Lock()
	shard.buckets[idx][userID] = struct{}{}
	shard.mu.Unlock()
}

func (t *ActiveUserTracker) GetActiveCount() int {
	uniqueUsers := make(map[string]struct{})

	for i := 0; i < numShards; i++ {
		s := t.shards[i]
		s.mu.RLock()
		for j := 0; j < numBuckets; j++ {
			for id := range s.buckets[j] {
				uniqueUsers[id] = struct{}{}
			}
		}
		s.mu.RUnlock()
	}
	return len(uniqueUsers)
}
