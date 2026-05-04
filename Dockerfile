FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy both mod files before downloading so the dependency layer is properly cached.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o server ./cmd/server

FROM alpine:3.19

RUN addgroup -S app && adduser -S app -G app

WORKDIR /app
COPY --from=builder /app/server .
COPY data/ data/

USER app
EXPOSE 8080
CMD ["./server"]
