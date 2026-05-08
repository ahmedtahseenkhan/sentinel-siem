package pipeline

import (
	"sync"

	"github.com/watchvault/watchvault/internal/opensearch"
)

type Buffer struct {
	mu       sync.Mutex
	items    []opensearch.BulkItem
	capacity int
}

func NewBuffer(capacity int) *Buffer {
	if capacity <= 0 {
		capacity = 10000
	}
	return &Buffer{
		items:    make([]opensearch.BulkItem, 0, capacity),
		capacity: capacity,
	}
}

func (b *Buffer) Add(item opensearch.BulkItem) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.items) >= b.capacity {
		return false
	}
	b.items = append(b.items, item)
	return true
}

func (b *Buffer) Drain() []opensearch.BulkItem {
	b.mu.Lock()
	defer b.mu.Unlock()
	items := b.items
	b.items = make([]opensearch.BulkItem, 0, b.capacity)
	return items
}

func (b *Buffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.items)
}
