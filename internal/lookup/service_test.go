package lookup_test

import (
	"context"
	"testing"

	"github.com/tiagowhuber/softserve-url-threat-lookup/internal/lookup"
)

func TestLookupSafeURL(t *testing.T) {
	svc := lookup.New()

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
}

func TestLookupMalware(t *testing.T) {
	svc := lookup.New()
	svc.AddURLs([]lookup.URLEntry{
		{URL: "evil.com/malware", Category: lookup.ThreatMalware},
	})

	r := svc.Lookup(context.Background(), "evil.com/malware")
	if r.Safe {
		t.Error("expected safe=false for malware URL")
	}
	if r.ThreatCategory != lookup.ThreatMalware {
		t.Errorf("expected malware, got %s", r.ThreatCategory)
	}
}

func TestLookupPhishing(t *testing.T) {
	svc := lookup.New()
	svc.AddURLs([]lookup.URLEntry{
		{URL: "phish.com/login", Category: lookup.ThreatPhishing},
	})

	r := svc.Lookup(context.Background(), "phish.com/login")
	if r.Safe {
		t.Error("expected safe=false for phishing URL")
	}
	if r.ThreatCategory != lookup.ThreatPhishing {
		t.Errorf("expected phishing, got %s", r.ThreatCategory)
	}
}

func TestLookupSpam(t *testing.T) {
	svc := lookup.New()
	svc.AddURLs([]lookup.URLEntry{
		{URL: "spam.example.com/pills", Category: lookup.ThreatSpam},
	})

	r := svc.Lookup(context.Background(), "spam.example.com/pills")
	if r.Safe {
		t.Error("expected safe=false for spam URL")
	}
	if r.ThreatCategory != lookup.ThreatSpam {
		t.Errorf("expected spam, got %s", r.ThreatCategory)
	}
}

func TestLookupUnlistedAfterOtherURLsAdded(t *testing.T) {
	svc := lookup.New()
	svc.AddURLs([]lookup.URLEntry{
		{URL: "evil.com/malware", Category: lookup.ThreatMalware},
	})

	r := svc.Lookup(context.Background(), "safe.com/page")
	if !r.Safe {
		t.Error("expected safe URL to remain safe when other URLs are blocked")
	}
}

func TestAddURLsOverwrite(t *testing.T) {
	svc := lookup.New()
	svc.AddURLs([]lookup.URLEntry{
		{URL: "url.com/path", Category: lookup.ThreatSpam},
	})
	svc.AddURLs([]lookup.URLEntry{
		{URL: "url.com/path", Category: lookup.ThreatMalware},
	})

	r := svc.Lookup(context.Background(), "url.com/path")
	if r.ThreatCategory != lookup.ThreatMalware {
		t.Errorf("expected overwritten category malware, got %s", r.ThreatCategory)
	}
}

func TestAddURLsBulk(t *testing.T) {
	svc := lookup.New()
	svc.AddURLs([]lookup.URLEntry{
		{URL: "a.com/1", Category: lookup.ThreatMalware},
		{URL: "b.com/2", Category: lookup.ThreatPhishing},
		{URL: "c.com/3", Category: lookup.ThreatSpam},
	})

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
