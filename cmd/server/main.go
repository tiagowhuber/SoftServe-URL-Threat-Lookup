package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"github.com/tiagowhuber/softserve-url-threat-lookup/internal/cache"
	"github.com/tiagowhuber/softserve-url-threat-lookup/internal/handler"
	"github.com/tiagowhuber/softserve-url-threat-lookup/internal/lookup"
	"github.com/tiagowhuber/softserve-url-threat-lookup/internal/metrics"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}

	rdb := redis.NewClient(&redis.Options{Addr: redisAddr})

	ctx := context.Background()
	for i := 1; i <= 30; i++ {
		if err := rdb.Ping(ctx).Err(); err == nil {
			break
		} else if i == 30 {
			logger.Error("Redis never became ready, exiting", slog.String("addr", redisAddr), slog.String("error", err.Error()))
			os.Exit(1)
		} else {
			logger.Info("waiting for Redis", slog.Int("attempt", i), slog.String("addr", redisAddr), slog.String("error", err.Error()))
			time.Sleep(time.Second)
		}
	}
	logger.Info("Redis ready")

	lruCache, err := cache.New(10_000, 5*time.Minute)
	if err != nil {
		logger.Error("failed to create LRU cache", slog.String("error", err.Error()))
		os.Exit(1)
	}

	metrics.Register()

	svc := lookup.New(rdb, lruCache)

	if err := loadSeedData(ctx, svc, logger); err != nil {
		logger.Error("failed to load seed data", slog.String("error", err.Error()))
	}

	h := handler.New(svc, logger)

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	router.GET("/urlinfo/1/:hostname_port/*path", h.LookupURL)
	router.POST("/admin/urls", h.AddURLs)
	router.GET("/health", h.Health)
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		logger.Info("server listening", slog.String("addr", srv.Addr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)

	select {
	case sig := <-quit:
		logger.Info("shutdown signal received", slog.String("signal", sig.String()))
	case err := <-serverErr:
		logger.Error("server error", slog.String("error", err.Error()))
		os.Exit(1)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	logger.Info("draining in-flight requests (up to 30s)")
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown error", slog.String("error", err.Error()))
		os.Exit(1)
	}
	logger.Info("server stopped cleanly")
}

func loadSeedData(ctx context.Context, svc *lookup.Service, logger *slog.Logger) error {
	data, err := os.ReadFile("data/blocklist.json")
	if err != nil {
		if os.IsNotExist(err) {
			logger.Info("no seed file found, skipping")
			return nil
		}
		return err
	}

	var entries []lookup.URLEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return err
	}

	if err := svc.AddURLs(ctx, entries); err != nil {
		return err
	}

	logger.Info("seed data loaded", slog.Int("count", len(entries)))
	return nil
}
