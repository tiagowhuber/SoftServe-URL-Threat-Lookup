.PHONY: build up down test seed stress install-k6

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

# Run k6 stress test against the running stack (make up first).
# Override base URL with: make stress BASE_URL=http://host:8080
stress:
	@which k6 > /dev/null 2>&1 || { echo "k6 not found – run: make install-k6"; exit 1; }
	k6 run $(if $(BASE_URL),--env BASE_URL=$(BASE_URL),) stress/k6.js
