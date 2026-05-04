package handler

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tiagowhuber/softserve-url-threat-lookup/internal/metrics"
)

type lookupResponse struct {
	URL            string    `json:"url"`
	Safe           bool      `json:"safe"`
	ThreatCategory string    `json:"threat_category"`
	Degraded       bool      `json:"degraded"`
	CheckedAt      time.Time `json:"checked_at"`
	Version        int       `json:"version"`
}

func (h *Handler) LookupURL(c *gin.Context) {
	start := time.Now()

	hostnamePort := c.Param("hostname_port")
	pathParam := c.Param("path")

	if len(pathParam) > 0 && pathParam[0] == '/' {
		pathParam = pathParam[1:]
	}

	targetURL := hostnamePort
	if pathParam != "" {
		targetURL += "/" + pathParam
	}
	if rawQuery := c.Request.URL.RawQuery; rawQuery != "" {
		targetURL += "?" + rawQuery
	}

	result := h.svc.Lookup(c.Request.Context(), targetURL)

	elapsed := time.Since(start)
	metrics.RequestsTotal.Inc()
	metrics.RequestDuration.Observe(elapsed.Seconds())
	if result.CacheHit {
		metrics.CacheHits.Inc()
	} else {
		metrics.CacheMisses.Inc()
	}
	if result.Degraded {
		metrics.ErrorsTotal.Inc()
	}

	errStr := ""
	if result.Err != nil {
		errStr = result.Err.Error()
	}

	h.logger.Info("url lookup",
		slog.String("url", targetURL),
		slog.Bool("safe", result.Safe),
		slog.Bool("cache_hit", result.CacheHit),
		slog.Float64("latency_ms", float64(elapsed.Microseconds())/1000.0),
		slog.Bool("degraded", result.Degraded),
		slog.String("error", errStr),
	)

	c.JSON(http.StatusOK, lookupResponse{
		URL:            result.URL,
		Safe:           result.Safe,
		ThreatCategory: string(result.ThreatCategory),
		Degraded:       result.Degraded,
		CheckedAt:      result.CheckedAt,
		Version:        result.Version,
	})
}
