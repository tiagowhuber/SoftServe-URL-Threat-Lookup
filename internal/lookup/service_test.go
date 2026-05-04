package lookup_test

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/tiagowhuber/softserve-url-threat-lookup/internal/cache"
	"github.com/tiagowhuber/softserve-url-threat-lookup/internal/lookup"
)

func newTestService(t *testing.T) (*lookup.Service, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	c, err := cache.New(100, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return lookup.New(rdb, c), mr
}

func TestLookupSafeURL(t *testing.T) {
	svc, mr := newTestService(t)
	defer mr.Close()

	r := svc.Lookup(context.Background(), "safe.com/page")
	if !r.Safe {
		t.Error("expected safe=true for unlisted URL")
	}
	if r.ThreatCategory != lookup.ThreatNone {
		t.Errorf("expected none, got %s", r.ThreatCategory)
	}
	if r.URL != "safe.com/page" {
		t.Errorf("expected URL echoed back, got %s", r.URL)
	}
	if r.Version != 1 {
		t.Errorf("expected version=1, got %d", r.Version)
	}
	if r.CheckedAt.IsZero() {
		t.Error("expected CheckedAt to be set")
	}
	if r.Degraded {
		t.Error("expected degraded=false")
	}
}

func TestLookupMalware(t *testing.T) {
	svc, mr := newTestService(t)
	defer mr.Close()

	mr.Set("evil.com/malware", `{"threat_category":"malware"}`)

	r := svc.Lookup(context.Background(), "evil.com/malware")
	if r.Safe {
		t.Error("expected safe=false for malware URL")
	}
	if r.ThreatCategory != lookup.ThreatMalware {
		t.Errorf("expected malware, got %s", r.ThreatCategory)
	}
}

func TestLookupPhishing(t *testing.T) {
	svc, mr := newTestService(t)
	defer mr.Close()

	mr.Set("phish.com/login", `{"threat_category":"phishing"}`)

	r := svc.Lookup(context.Background(), "phish.com/login")
	if r.Safe {
		t.Error("expected safe=false for phishing URL")
	}
	if r.ThreatCategory != lookup.ThreatPhishing {
		t.Errorf("expected phishing, got %s", r.ThreatCategory)
	}
}

func TestLookupSpam(t *testing.T) {
	svc, mr := newTestService(t)
	defer mr.Close()

	mr.Set("spam.example.com/pills", `{"threat_category":"spam"}`)

	r := svc.Lookup(context.Background(), "spam.example.com/pills")
	if r.Safe {
		t.Error("expected safe=false for spam URL")
	}
	if r.ThreatCategory != lookup.ThreatSpam {
		t.Errorf("expected spam, got %s", r.ThreatCategory)
	}
}

func TestLookupUnlistedAfterOtherURLsAdded(t *testing.T) {
	svc, mr := newTestService(t)
	defer mr.Close()

	mr.Set("evil.com/malware", `{"threat_category":"malware"}`)

	r := svc.Lookup(context.Background(), "safe.com/page")
	if !r.Safe {
		t.Error("expected safe URL to remain safe when other URLs are blocked")
	}
}

func TestLookupCacheHit(t *testing.T) {
	svc, mr := newTestService(t)
	defer mr.Close()

	mr.Set("evil.com/phishing", `{"threat_category":"phishing"}`)

	r1 := svc.Lookup(context.Background(), "evil.com/phishing")
	if r1.CacheHit {
		t.Error("first lookup should be a Redis hit, not LRU hit")
	}

	r2 := svc.Lookup(context.Background(), "evil.com/phishing")
	if !r2.CacheHit {
		t.Error("second lookup should be served from LRU cache")
	}
	if r2.ThreatCategory != lookup.ThreatPhishing {
		t.Errorf("cached result wrong: got %s", r2.ThreatCategory)
	}
}

func TestLookupNegativeCached(t *testing.T) {
	svc, mr := newTestService(t)
	defer mr.Close()

	r1 := svc.Lookup(context.Background(), "safe.com/page")
	if r1.CacheHit {
		t.Error("first lookup should miss cache")
	}

	r2 := svc.Lookup(context.Background(), "safe.com/page")
	if !r2.CacheHit {
		t.Error("negative answer should be served from LRU on second lookup")
	}
}

func TestAddURLs(t *testing.T) {
	svc, mr := newTestService(t)
	defer mr.Close()

	if err := svc.AddURLs(context.Background(), []lookup.URLEntry{
		{URL: "new-evil.com/path", Category: lookup.ThreatSpam},
	}); err != nil {
		t.Fatal(err)
	}

	r := svc.Lookup(context.Background(), "new-evil.com/path")
	if r.Safe {
		t.Error("expected URL to be blocked after AddURLs")
	}
	if r.ThreatCategory != lookup.ThreatSpam {
		t.Errorf("expected spam, got %s", r.ThreatCategory)
	}
}

func TestAddURLsInvalidatesCache(t *testing.T) {
	svc, mr := newTestService(t)
	defer mr.Close()

	// Warm the negative cache entry.
	svc.Lookup(context.Background(), "url.com/path")

	if err := svc.AddURLs(context.Background(), []lookup.URLEntry{
		{URL: "url.com/path", Category: lookup.ThreatMalware},
	}); err != nil {
		t.Fatal(err)
	}

	r := svc.Lookup(context.Background(), "url.com/path")
	if r.Safe {
		t.Error("expected URL to be blocked after cache invalidation")
	}
}

func TestDegradedMode(t *testing.T) {
	svc, mr := newTestService(t)
	mr.Close() // simulate Redis going down

	r := svc.Lookup(context.Background(), "any.com/path")
	if !r.Safe {
		t.Error("expected fail-open (safe=true) when Redis is unreachable")
	}
	if !r.Degraded {
		t.Error("expected degraded=true when Redis is unreachable")
	}
}

func TestDegradedCacheServesPriorHit(t *testing.T) {
	svc, mr := newTestService(t)
	defer mr.Close()

	mr.Set("evil.com/path", `{"threat_category":"malware"}`)

	// Warm the LRU cache while Redis is up.
	svc.Lookup(context.Background(), "evil.com/path")

	// Kill Redis.
	mr.Close()

	// Next lookup hits LRU — should not be degraded.
	r := svc.Lookup(context.Background(), "evil.com/path")
	if r.Degraded {
		t.Error("expected cached result to be served without degraded flag")
	}
	if r.ThreatCategory != lookup.ThreatMalware {
		t.Errorf("expected malware from LRU, got %s", r.ThreatCategory)
	}
}
