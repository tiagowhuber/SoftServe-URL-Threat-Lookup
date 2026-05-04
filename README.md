# URL Threat Lookup

A URL safety lookup service built with Go (Gin) and Redis.

## One-command startup

```bash
docker-compose up --build
```

The service starts on **port 8080**. Seed data from `data/blocklist.json` is loaded automatically on startup — no additional setup is required.

---

## curl Examples

### 1. Safe URL
```bash
curl http://localhost:8080/urlinfo/1/safe.example.com/about
```
```json
{
  "url": "safe.example.com/about",
  "safe": true,
  "threat_category": "none",
  "degraded": false,
  "checked_at": "2026-04-30T14:00:00Z",
  "version": 1
}
```

### 2. Malware URL (seeded on startup)
```bash
curl http://localhost:8080/urlinfo/1/malware.example.com/download%2Fvirus.exe
```
```json
{
  "url": "malware.example.com/download/virus.exe",
  "safe": false,
  "threat_category": "malware",
  "degraded": false,
  "checked_at": "2026-04-30T14:00:00Z",
  "version": 1
}
```

### 3. Phishing URL (seeded on startup)
```bash
curl "http://localhost:8080/urlinfo/1/phishing.example.com/login%2Fsteal-credentials"
```
```json
{
  "url": "phishing.example.com/login/steal-credentials",
  "safe": false,
  "threat_category": "phishing",
  "degraded": false,
  "checked_at": "2026-04-30T14:00:00Z",
  "version": 1
}
```

### 4. Health check
```bash
curl http://localhost:8080/health
```
```json
{"redis": "ok", "status": "ok"}
```
Returns `503` with `"status": "degraded"` when Redis is unreachable.

### 5. Add URLs to the blocklist
```bash
curl -X POST http://localhost:8080/admin/urls \
  -H "Content-Type: application/json" \
  -d '[{"url":"new-evil.com/malware","threat_category":"malware"}]'
```
```json
{"added": 1}
```

### 6. Prometheus metrics
```bash
curl http://localhost:8080/metrics
```

---

## Response Schema

| Field | Type | Description |
|---|---|---|
| `url` | string | The full URL that was checked (`hostname:port/path?query`) |
| `safe` | bool | `true` when the URL is not in the blocklist |
| `threat_category` | string | `"none"` \| `"malware"` \| `"phishing"` \| `"spam"` |
| `degraded` | bool | `true` when Redis was unreachable and the service is failing open |
| `checked_at` | string (RFC 3339) | UTC timestamp of when the lookup was performed |
| `version` | int | Schema version, currently `1` |

---

## Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/urlinfo/1/{hostname_and_port}/{path_and_query}` | Look up a URL's threat status |
| `POST` | `/admin/urls` | Add URLs to the blocklist (JSON array) |
| `GET` | `/health` | Redis connectivity and overall service health |
| `GET` | `/metrics` | Prometheus metrics in exposition format |

---

## Makefile targets

| Target | Description |
|---|---|
| `make build` | Build the Docker image |
| `make up` | Start the full stack (app + Redis) |
| `make down` | Stop and remove containers |
| `make test` | Run all unit and integration tests |
| `make seed` | Re-load `data/blocklist.json` via the admin API |

---

## Architecture

```
caller → GET /urlinfo/1/{host}/{path} → Handler
                                           │
                                    LRU Cache (10k entries, 5min TTL)
                                           │ miss
                                         Redis
                                           │ not found
                                       safe=true
```

Each service instance is **stateless** — all durable state lives in Redis. The in-process LRU cache absorbs repeated lookups for hot URLs. On Redis failure the service **fails open** (`safe=true`, `degraded=true`) to keep the proxy unblocked, while signalling the degraded state to the caller.

---

## Scaling Considerations

### Bloom filter for memory-efficient lookups

At very large blocklist sizes (tens of millions of entries), a Bloom filter can act as a probabilistic pre-filter with ~10 bits per entry regardless of URL length. A `false` result is a guaranteed "safe" answer — no false negatives — short-circuiting the Redis round-trip for the vast majority of traffic. Libraries such as [bits-and-blooms/bloom](https://github.com/bits-and-blooms/bloom) integrate with the existing service layer.

### Horizontal scaling behind a load balancer

Each instance is stateless — spinning up additional replicas behind NGINX, HAProxy, or a cloud load balancer requires no code changes. The LRU cache is per-process; each node warms independently, which is acceptable because Redis is the authoritative source.

### Redis Cluster for sharding

A single Redis primary becomes the bottleneck at high write rates or very large keyspaces. Redis Cluster shards keys across multiple primaries using consistent hashing. The `go-redis` client supports Cluster mode via `redis.NewClusterClient` — a drop-in replacement for the single-node client used here.

### Cross-region replication

For global deployments, a Redis primary in one region can be replicated to read replicas in other regions. Blocklist updates (writes) always target the primary; lookups in remote regions hit the local replica, which may lag by a few hundred milliseconds. For tighter consistency, all writes and reads route through a single primary at the cost of cross-region latency on every lookup.

### Cache invalidation across instances

`POST /admin/urls` invalidates the LRU cache on the instance that receives the request. Peer instances continue to serve the stale cached answer until their TTL expires (5 minutes). A Redis Pub/Sub channel or Redis Streams consumer group can broadcast invalidation events to all instances, keeping caches consistent without point-to-point coordination.

### Blocklist update strategy

At 5,000 URLs/day arriving every 10 minutes (~35 URLs per window), the current admin API is sufficient. At higher rates or for auditability, consider a pull-based versioned feed: the updater publishes a signed diff to object storage every interval; each instance polls, diffs against its last-seen version, and applies adds/removes. This makes updates durable, replayable, and decoupled from the service's write path.
