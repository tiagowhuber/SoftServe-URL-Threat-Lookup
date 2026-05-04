package handler

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/tiagowhuber/softserve-url-threat-lookup/internal/lookup"
)

// AddURLs handles POST /admin/urls.
func (h *Handler) AddURLs(c *gin.Context) {
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

	if err := h.svc.AddURLs(c.Request.Context(), entries); err != nil {
		h.logger.Error("failed to store urls", slog.String("error", err.Error()), slog.Int("count", len(entries)))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store urls"})
		return
	}

	h.logger.Info("blocklist updated", slog.Int("added", len(entries)))
	c.JSON(http.StatusOK, gin.H{"added": len(entries)})
}
