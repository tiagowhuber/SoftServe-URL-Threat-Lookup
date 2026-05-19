package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	RequestsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "url_lookup_requests_total",
		Help: "Total URL lookup requests handled.",
	})

	ErrorsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "url_lookup_errors_total",
		Help: "Total requests that activated degraded mode.",
	})

	// Buckets cover the expected fast path (sub-ms LRU, low-ms Redis) through
	// worst-case tail latency so p99 is always observable.
	RequestDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "url_lookup_duration_seconds",
		Help:    "End-to-end request latency in seconds.",
		Buckets: []float64{0.001, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0},
	})

	CacheHits = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "url_lookup_cache_hits_total",
		Help: "Total LRU cache hits.",
	})

	CacheMisses = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "url_lookup_cache_misses_total",
		Help: "Total LRU cache misses.",
	})

	WriteRequestsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "url_write_requests_total",
		Help: "Total POST /admin/urls requests handled.",
	})

	WriteURLsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "url_write_urls_total",
		Help: "Total individual URLs added to the blocklist.",
	})

	WriteDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "url_write_duration_seconds",
		Help:    "End-to-end latency of POST /admin/urls in seconds.",
		Buckets: []float64{0.001, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0},
	})
)

func Register() {
	prometheus.MustRegister(
		RequestsTotal,
		ErrorsTotal,
		RequestDuration,
		CacheHits,
		CacheMisses,
		WriteRequestsTotal,
		WriteURLsTotal,
		WriteDuration,
	)
}
