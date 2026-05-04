package cache

import (
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

type entry struct {
	value     string
	expiresAt time.Time
}

// TTLCache is a thread-safe LRU cache with per-entry expiry.
type TTLCache struct {
	mu  sync.Mutex
	lru *lru.Cache[string, entry]
	ttl time.Duration
}

func New(maxEntries int, ttl time.Duration) (*TTLCache, error) {
	l, err := lru.New[string, entry](maxEntries)
	if err != nil {
		return nil, err
	}
	return &TTLCache{lru: l, ttl: ttl}, nil
}

func (c *TTLCache) Get(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.lru.Get(key)
	if !ok {
		return "", false
	}
	if time.Now().After(e.expiresAt) {
		c.lru.Remove(key)
		return "", false
	}
	return e.value, true
}

func (c *TTLCache) Set(key, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lru.Add(key, entry{value: value, expiresAt: time.Now().Add(c.ttl)})
}

func (c *TTLCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lru.Remove(key)
}

func (c *TTLCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}
