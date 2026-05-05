package lookup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/tiagowhuber/softserve-url-threat-lookup/internal/cache"
)

type ThreatCategory string

const (
	ThreatNone     ThreatCategory = "none"
	ThreatMalware  ThreatCategory = "malware"
	ThreatPhishing ThreatCategory = "phishing"
	ThreatSpam     ThreatCategory = "spam"
)

type threatInfo struct {
	Category ThreatCategory `json:"threat_category"`
}

const MaxURLLength = 2048

var validCategories = map[ThreatCategory]bool{
	ThreatNone:     true,
	ThreatMalware:  true,
	ThreatPhishing: true,
	ThreatSpam:     true,
}

type URLEntry struct {
	URL      string         `json:"url"`
	Category ThreatCategory `json:"threat_category"`
}

func (e URLEntry) Validate() error {
	if e.URL == "" {
		return errors.New("url is required")
	}
	if len(e.URL) > MaxURLLength {
		return fmt.Errorf("url exceeds maximum length of %d", MaxURLLength)
	}
	if !validCategories[e.Category] {
		return fmt.Errorf("invalid threat_category %q", e.Category)
	}
	return nil
}

type Result struct {
	URL            string
	Safe           bool
	ThreatCategory ThreatCategory
	Degraded       bool
	CacheHit       bool
	CheckedAt      time.Time
	Version        int
	Err            error
}

type Service struct {
	rdb   *redis.Client
	cache *cache.TTLCache
}

func New(rdb *redis.Client, c *cache.TTLCache) *Service {
	return &Service{rdb: rdb, cache: c}
}

func (s *Service) Lookup(ctx context.Context, url string) Result {
	now := time.Now().UTC()

	// LRU hit — avoid the Redis round-trip on hot URLs.
	if raw, ok := s.cache.Get(url); ok {
		var info threatInfo
		if err := json.Unmarshal([]byte(raw), &info); err == nil {
			return Result{
				URL:            url,
				Safe:           info.Category == ThreatNone,
				ThreatCategory: info.Category,
				CacheHit:       true,
				CheckedAt:      now,
				Version:        1,
			}
		}
	}

	raw, err := s.rdb.Get(ctx, url).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			s.cache.Set(url, `{"threat_category":"none"}`)
			return Result{
				URL:            url,
				Safe:           true,
				ThreatCategory: ThreatNone,
				CheckedAt:      now,
				Version:        1,
			}
		}
		// Redis unreachable — fail open.
		return Result{
			URL:            url,
			Safe:           true,
			ThreatCategory: ThreatNone,
			Degraded:       true,
			CheckedAt:      now,
			Version:        1,
			Err:            err,
		}
	}

	s.cache.Set(url, raw)

	var info threatInfo
	if jsonErr := json.Unmarshal([]byte(raw), &info); jsonErr != nil {
		info = threatInfo{Category: ThreatNone}
	}

	return Result{
		URL:            url,
		Safe:           info.Category == ThreatNone,
		ThreatCategory: info.Category,
		CheckedAt:      now,
		Version:        1,
	}
}

func (s *Service) AddURLs(ctx context.Context, entries []URLEntry) error {
	pipe := s.rdb.Pipeline()
	for _, e := range entries {
		data, err := json.Marshal(threatInfo{Category: e.Category})
		if err != nil {
			return err
		}
		pipe.Set(ctx, e.URL, string(data), 0)
		// Invalidate stale LRU entries immediately.
		s.cache.Delete(e.URL)
	}
	_, err := pipe.Exec(ctx)
	return err
}

func (s *Service) Ping(ctx context.Context) error {
	return s.rdb.Ping(ctx).Err()
}
