.PHONY: build up down test seed stress stress-reads stress-writes stress-mixed install-k6 open-grafana open-prometheus

build:
	docker-compose build

up:
	docker-compose up --build

down:
	docker-compose down

test:
	go test -v -count=1 ./...

# Re-seeds the running service via the admin API.
# Requires the stack to be up (make up) and curl to be available.
seed:
	curl -s -X POST http://localhost:8080/admin/urls \
		-H "Content-Type: application/json" \
		-d @data/blocklist.json

# Install k6 via the official snap package. (requires snap)
install-k6:
	sudo snap install k6

# Run k6 stress tests. Override base URL with: make stress-reads BASE_URL=http://host:8080
K6_CHECK := @which k6 > /dev/null 2>&1 || { echo "k6 not found – run: make install-k6"; exit 1; }
K6_URL   := $(if $(BASE_URL),--env BASE_URL=$(BASE_URL),)

# Read-only: lookups only (warm LRU + cold Redis scenarios).
stress-reads:
	$(K6_CHECK)
	k6 run $(K6_URL) stress/reads.js

# Write-only: POST /admin/urls as fast as possible.
# Override batch size with: make stress-writes BATCH_SIZE=10
stress-writes:
	$(K6_CHECK)
	k6 run $(K6_URL) $(if $(BATCH_SIZE),--env BATCH_SIZE=$(BATCH_SIZE),) stress/writes.js

# Mixed: reads + writes concurrently (original combined test).
stress-mixed:
	$(K6_CHECK)
	k6 run $(K6_URL) stress/k6.js

# Alias: stress → mixed (backward compat).
stress: stress-mixed

# Open Grafana dashboard in the default browser (stack must be up).
open-grafana:
	xdg-open http://localhost:3000/d/url-threat-lookup 2>/dev/null || open http://localhost:3000/d/url-threat-lookup

# Open Prometheus expression browser.
open-prometheus:
	xdg-open http://localhost:9090 2>/dev/null || open http://localhost:9090
