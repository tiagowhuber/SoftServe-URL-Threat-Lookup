.PHONY: build up down test seed

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
