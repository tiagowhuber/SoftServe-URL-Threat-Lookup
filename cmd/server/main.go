package main

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/tiagowhuber/softserve-url-threat-lookup/internal/handler"
	"github.com/tiagowhuber/softserve-url-threat-lookup/internal/lookup"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	svc := lookup.New()
	h := handler.New(svc, logger)

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	router.GET("/urlinfo/1/:hostname_port/*path", h.LookupURL)

	logger.Info("server listening", slog.String("addr", ":8080"))
	if err := router.Run(":8080"); err != nil && err != http.ErrServerClosed {
		logger.Error("server error", slog.String("error", err.Error()))
		os.Exit(1)
	}
}
