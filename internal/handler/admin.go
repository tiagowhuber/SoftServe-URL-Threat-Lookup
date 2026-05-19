package handler

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tiagowhuber/softserve-url-threat-lookup/internal/lookup"
	"github.com/tiagowhuber/softserve-url-threat-lookup/internal/metrics"
)

// AddURLs handles POST /admin/urls.
func (h *Handler) AddURLs(c *gin.Context) {
	start := time.Now()
	metrics.WriteRequestsTotal.Inc()

	var entries []lookup.URLEntry
	if err := c.ShouldBindJSON(&entries); err != nil {
		h.logger.Error("invalid request body", slog.String("error", err.Error()))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if len(entries) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "empty entries list"})
		return
	}

	for i, e := range entries {
		if err := e.Validate(); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("entry %d: %s", i, err)})
			return
		}
	}

	if err := h.svc.AddURLs(c.Request.Context(), entries); err != nil {
		h.logger.Error("failed to store urls", slog.String("error", err.Error()), slog.Int("count", len(entries)))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store urls"})
		return
	}

	metrics.WriteURLsTotal.Add(float64(len(entries)))
	metrics.WriteDuration.Observe(time.Since(start).Seconds())
	h.logger.Info("blocklist updated", slog.Int("added", len(entries)))
	c.JSON(http.StatusOK, gin.H{"added": len(entries)})
}
