package lookup

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
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

type URLEntry struct {
	URL      string
	Category ThreatCategory
}

type Result struct {
	URL            string
	Safe           bool
	ThreatCategory ThreatCategory
	Degraded       bool
	CheckedAt      time.Time
	Version        int
	Err            error
}

type Service struct {
	rdb *redis.Client
}

func New(rdb *redis.Client) *Service {
	return &Service{rdb: rdb}
}

func (s *Service) Lookup(ctx context.Context, url string) Result {
	now := time.Now().UTC()

	raw, err := s.rdb.Get(ctx, url).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
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
	}
	_, err := pipe.Exec(ctx)
	return err
}

func (s *Service) Ping(ctx context.Context) error {
	return s.rdb.Ping(ctx).Err()
}
