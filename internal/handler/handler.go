package handler

import (
	"log/slog"

	"github.com/tiagowhuber/softserve-url-threat-lookup/internal/lookup"
)

type Handler struct {
	svc    *lookup.Service
	logger *slog.Logger
}

func New(svc *lookup.Service, logger *slog.Logger) *Handler {
	return &Handler{svc: svc, logger: logger}
}
