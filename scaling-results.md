# Scaling Results

## Phase 1 — Single Process (baseline)

**Date:** 2026-05-19
**k6 scenario duration:** 100s each

### Reads (`make stress-reads`)

| Metric | Value |
|--------|-------|
| Peak req/sec | ~24,574 |
| p99 latency — warm (same URLs, LRU hits) | 32.2 ms |
| p99 latency — cold (unique URLs, Redis hits) | 44.67 ms |
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
- Reads top out at ~24.5K req/sec; writes at ~19.4K req/sec (single Go process + Redis pipeline)
- Write latency (avg 1.8ms) is lower than read latency (avg 5.7ms) — Redis pipeline batching is very efficient
- URLs/sec is 5× write req/sec because each request posts a batch of 5
- 0% errors under full load — the service is stable at these throughputs

---

## Phase 2 — NGINX + N Replicas

### 2 Replicas

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

### 4 Replicas

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

### 8 Replicas

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
