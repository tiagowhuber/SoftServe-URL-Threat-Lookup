package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type healthResponse struct {
	Redis  string `json:"redis"`
	Status string `json:"status"`
}

// Health handles GET /health.
// Returns 503 when Redis is unreachable so load balancers can drain the instance.
func (h *Handler) Health(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
	defer cancel()

	redisStatus := "ok"
	overallStatus := "ok"
	statusCode := http.StatusOK

	if err := h.svc.Ping(ctx); err != nil {
		redisStatus = "unreachable"
		overallStatus = "degraded"
		statusCode = http.StatusServiceUnavailable
	}

	c.JSON(statusCode, healthResponse{
		Redis:  redisStatus,
		Status: overallStatus,
	})
}
