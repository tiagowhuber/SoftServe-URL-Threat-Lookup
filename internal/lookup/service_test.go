package lookup_test

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/tiagowhuber/softserve-url-threat-lookup/internal/lookup"
)

func newTestService(t *testing.T) (*lookup.Service, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return lookup.New(rdb), mr
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

func TestAddURLs(t *testing.T) {
	svc, mr := newTestService(t)
	defer mr.Close()

	entries := []lookup.URLEntry{
		{URL: "new-evil.com/path", Category: lookup.ThreatSpam},
	}
	if err := svc.AddURLs(context.Background(), entries); err != nil {
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

func TestAddURLsBulk(t *testing.T) {
	svc, mr := newTestService(t)
	defer mr.Close()

	err := svc.AddURLs(context.Background(), []lookup.URLEntry{
		{URL: "a.com/1", Category: lookup.ThreatMalware},
		{URL: "b.com/2", Category: lookup.ThreatPhishing},
		{URL: "c.com/3", Category: lookup.ThreatSpam},
	})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		url  string
		want lookup.ThreatCategory
	}{
		{"a.com/1", lookup.ThreatMalware},
		{"b.com/2", lookup.ThreatPhishing},
		{"c.com/3", lookup.ThreatSpam},
		{"safe.com", lookup.ThreatNone},
	}
	for _, tc := range cases {
		r := svc.Lookup(context.Background(), tc.url)
		if r.ThreatCategory != tc.want {
			t.Errorf("url=%s: expected %s, got %s", tc.url, tc.want, r.ThreatCategory)
		}
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
