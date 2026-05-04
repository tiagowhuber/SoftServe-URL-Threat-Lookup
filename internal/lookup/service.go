package lookup

import (
	"context"
	"sync"
	"time"
)

type ThreatCategory string

const (
	ThreatNone     ThreatCategory = "none"
	ThreatMalware  ThreatCategory = "malware"
	ThreatPhishing ThreatCategory = "phishing"
	ThreatSpam     ThreatCategory = "spam"
)

type Result struct {
	URL            string
	Safe           bool
	ThreatCategory ThreatCategory
	CheckedAt      time.Time
	Version        int
}

type Service struct {
	mu        sync.RWMutex
	blocklist map[string]ThreatCategory
}

func New() *Service {
	return &Service{blocklist: make(map[string]ThreatCategory)}
}

func (s *Service) Lookup(_ context.Context, url string) Result {
	s.mu.RLock()
	cat, blocked := s.blocklist[url]
	s.mu.RUnlock()

	if !blocked {
		cat = ThreatNone
	}

	return Result{
		URL:            url,
		Safe:           !blocked,
		ThreatCategory: cat,
		CheckedAt:      time.Now().UTC(),
		Version:        1,
	}
}
