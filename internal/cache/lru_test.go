package cache_test

import (
	"testing"
	"time"

	"github.com/tiagowhuber/softserve-url-threat-lookup/internal/cache"
)

func TestSetGet(t *testing.T) {
	c, err := cache.New(100, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	c.Set("key1", "value1")
	val, ok := c.Get("key1")
	if !ok || val != "value1" {
		t.Errorf("expected value1, got %q (ok=%v)", val, ok)
	}
}

func TestMiss(t *testing.T) {
	c, err := cache.New(100, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	_, ok := c.Get("nonexistent")
	if ok {
		t.Error("expected cache miss for unknown key")
	}
}

func TestExpiry(t *testing.T) {
	c, err := cache.New(100, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}

	c.Set("key1", "value1")
	time.Sleep(100 * time.Millisecond)
	_, ok := c.Get("key1")
	if ok {
		t.Error("expected entry to be expired after TTL")
	}
}

func TestDelete(t *testing.T) {
	c, err := cache.New(100, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	c.Set("key1", "value1")
	c.Delete("key1")
	_, ok := c.Get("key1")
	if ok {
		t.Error("expected entry to be absent after Delete")
	}
}

func TestMaxSize(t *testing.T) {
	c, err := cache.New(3, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	c.Set("k1", "v1")
	c.Set("k2", "v2")
	c.Set("k3", "v3")
	c.Set("k4", "v4") // evicts LRU (k1)

	if n := c.Len(); n > 3 {
		t.Errorf("cache exceeded max size: got %d, want ≤3", n)
	}
}

func TestOverwrite(t *testing.T) {
	c, err := cache.New(100, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	c.Set("key", "old")
	c.Set("key", "new")
	val, ok := c.Get("key")
	if !ok || val != "new" {
		t.Errorf("expected new, got %q", val)
	}
}
