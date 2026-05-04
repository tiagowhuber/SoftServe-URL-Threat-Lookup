package handler

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type lookupResponse struct {
	URL            string    `json:"url"`
	Safe           bool      `json:"safe"`
	ThreatCategory string    `json:"threat_category"`
	CheckedAt      time.Time `json:"checked_at"`
	Version        int       `json:"version"`
}

func (h *Handler) LookupURL(c *gin.Context) {
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

	h.logger.Info("url lookup",
		slog.String("url", targetURL),
		slog.Bool("safe", result.Safe),
	)

	c.JSON(http.StatusOK, lookupResponse{
		URL:            result.URL,
		Safe:           result.Safe,
		ThreatCategory: string(result.ThreatCategory),
		CheckedAt:      result.CheckedAt,
		Version:        result.Version,
	})
}
