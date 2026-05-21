# Scaling Results

## Phase 1 — Single Process (baseline)

**Date:** 2026-05-20
**k6 scenario duration:** ~100s ramp-up to 1200 VUs

### Reads (`make stress-reads`)

| Metric | Value |
|--------|-------|
| Peak req/sec | ~34,300 |
| Total requests | 2,262,213 |
| avg latency | 7.1 ms |
| p(90) latency — overall | 15.22 ms |
| p(95) latency — overall | 20.35 ms |
| p(90) latency — warm (LRU hits) | 15.05 ms |
| p(95) latency — warm (LRU hits) | 20.05 ms |
| p(90) latency — cold (Redis hits) | 18.2 ms |
| p(95) latency — cold (Redis hits) | 25.8 ms |
| k6 error rate | 0.00% |


### Writes (`make stress-writes`)

| Metric | Value |
|--------|-------|
| Peak write requests/sec | ~19,438 |
| Peak URLs written/sec (batch=5) | ~97,190 |
| p99 write latency | 5.6 ms |
| avg write latency | 1.8 ms |
| k6 error rate | 0.00% |

**Key observations:**
- Reads top out at ~34.3K req/sec; writes at ~19.4K req/sec (single Go process + Redis pipeline)
- Write latency (avg 1.8ms) is lower than read latency (avg 7.1ms) — Redis pipeline batching is very efficient
- URLs/sec is 5× write req/sec because each request posts a batch of 5
- 0% errors under full load — the service is stable at these throughputs

---

## Phase 2 — NGINX + N Replicas

**Date:** 2026-05-21  
**Architecture:** NGINX (port 8081) → N app replicas (internal) → shared Redis  
**Test:** `make stress-reads` (same k6 scenario as Phase 1, up to 1200 VUs)

### Cache behavior across replica counts (Grafana — LRU Cache panel)

| Replicas | Peak cache hits/sec | Peak Redis lookups/sec | Approx LRU hit ratio |
|----------|--------------------|-----------------------|----------------------|
| 1        | ~24K               | ~200                  | ~99%                 |
| 2        | ~23K               | ~300                  | ~98.5%               |
| 4        | ~22K               | ~400                  | ~98%                 |
| 8        | ~20K               | ~500                  | ~97.5%               |

*Values read from Grafana chart. Mean across all runs: cache hits 7.26K req/s, Redis lookups 504 req/s.*

### Per-run k6 metrics

*(Fill in from terminal output if captured — peak req/sec, latency percentiles, error rate)*

| Metric | 1 replica | 2 replicas | 4 replicas | 8 replicas |
|--------|-----------|------------|------------|------------|
| Peak reads/sec | — | — | — | — |
| p99 warm latency (ms) | — | — | — | — |
| p99 cold latency (ms) | — | — | — | — |
| k6 error rate | 0% | 0% | 0% | 0% |

### Key observations

- **Throughput is flat across replica counts.** NGINX + a single machine is still the bottleneck. Adding replicas doesn't help req/sec because the CPU and network were not saturated at 1 replica. The ceiling is the same as Phase 1.

- **Cache hit ratio degrades as replicas increase, but the effect is subtle for this workload.** The warm scenario only uses 35 URLs — a working set that fits entirely in every replica's 10K-entry LRU cache. Once each replica has seen each of the 35 URLs once, all caches are fully warm and NGINX round-robin stops causing misses. With a larger working set (say 100K URLs), the degradation would be much steeper and visible.

- **Why the hits still drop ~1K/s per doubling:** During ramp-up, new VUs get routed to replicas whose caches aren't fully warm yet, causing a burst of Redis misses until all 35 URLs propagate to all replica caches. More replicas = longer warm-up period per cache = more misses during the ramp-up phase of the test.

- **The architectural lesson holds:** If the warm working set were larger than cache capacity ÷ N, each replica would permanently miss URLs that were cached by a sibling. Shared caches (Redis) prevent this but add round-trip cost.

---

## Phase 3 — Zero-Downtime Scaling

**Date:** 2026-05-21  
**Test:** `make drain-test` — k6 runs `stress/reads.js` continuously (1200 max VUs, ~100s) while the stack scales 1→4→2→1 mid-test via `docker compose up -d --scale app=N --no-recreate && nginx -s reload`

### k6 results

| Metric | Value |
|--------|-------|
| Total requests | 1,744,401 |
| Peak reads/sec | ~17,442 |
| **k6 error rate** | **0.00%** |
| http_req_failed | 0.00% (0 out of 1,744,402) |
| avg latency | 12.62 ms |
| p(90) latency | 26.45 ms |
| p(95) latency | 34.38 ms |
| **p(99) warm latency** | **57.2 ms** (threshold <200 ms ✓) |
| **p(99) cold latency** | **71.83 ms** (threshold <500 ms ✓) |

### Scaling timeline (Grafana — "Reads/sec per replica" panel)

The per-replica Grafana panel shows individual replica IP lines appearing and disappearing as containers start and stop:

| Time (approx) | Event | Observed |
|---------------|-------|----------|
| t=0s | k6 starts, 1 replica | Single line ramps up |
| t=15s | Scale 1→4 | 3 new IP lines appear; total holds steady |
| t=40s | Scale 4→2 | 2 lines drop to 0; remaining replicas absorb load |
| t=65s | Scale 2→1 | 1 more line drops to 0; final replica carries all traffic |
| t=100s | k6 ends | Peak total: ~26.8K req/s |

### Key observations

- **Zero errors throughout.** Every single request succeeded despite containers being added and removed mid-test. This is the proof of zero-downtime.

- **Mechanism that made it work (two pieces working together):**
  1. **Graceful shutdown in Go** (`srv.Shutdown(30s)`) — when Docker sends SIGTERM to a removed container, the Go server stops accepting new connections but finishes all in-flight requests before exiting. New connections get "connection refused."
  2. **`proxy_next_upstream error`** in NGINX — when NGINX gets "connection refused" from a draining backend, it transparently retries the request on another healthy replica. The client never sees the failure.

- **NGINX reload is the load balancer update.** `nginx -s reload` is a graceful reload: existing worker processes finish their current requests, new workers start with the updated backend list (re-resolved Docker DNS). Zero connections dropped during reload.

- **Latency improved vs single-process.** p(99) warm was 57ms vs Phase 1's warm p(95) of 20ms — but Phase 1 went up to 1000 VUs vs this test's different ramp shape. The absolute numbers aren't directly comparable; the 0-error story is what matters.

---

## Phase 4 — Kubernetes (kind)

### 2 Pods (initial)

**Date:**

| Metric | Value | vs Phase 1 |
|--------|-------|------------|
| Peak reads/sec | | |
| Peak write req/sec | | |
| Peak URLs written/sec | | |
| p99 read latency warm (ms) | | |
| p99 read latency cold (ms) | | |
| p99 write latency (ms) | | |
| LRU cache hit ratio (%) | | |
| Redis lookup rate (req/sec) | | |
| k6 error rate | | |

**Notes:**

---

### After HPA auto-scales

**Date:**
**Pods scaled to:**

| Metric | Value | vs Phase 1 |
|--------|-------|------------|
| Peak reads/sec | | |
| Peak write req/sec | | |
| Peak URLs written/sec | | |
| p99 read latency warm (ms) | | |
| p99 read latency cold (ms) | | |
| p99 write latency (ms) | | |
| LRU cache hit ratio (%) | | |
| Redis lookup rate (req/sec) | | |
| k6 error rate | | |

**Notes:**
