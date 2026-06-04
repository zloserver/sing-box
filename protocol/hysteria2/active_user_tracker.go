package hysteria2

import "sync"

type ConnectionTracker struct {
	mu    sync.RWMutex
	conns map[string]int
}

func NewConnectionTracker() *ConnectionTracker {
	return &ConnectionTracker{conns: make(map[string]int)}
}

func (t *ConnectionTracker) Add(id string) {
	t.mu.Lock()
	t.conns[id]++
	t.mu.Unlock()
}

func (t *ConnectionTracker) Remove(id string) {
	t.mu.Lock()
	t.conns[id]--
	if t.conns[id] <= 0 {
		delete(t.conns, id)
	}
	t.mu.Unlock()
}

func (t *ConnectionTracker) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.conns)
}
