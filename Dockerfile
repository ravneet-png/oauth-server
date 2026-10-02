# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Build stage
# ---------------------------------------------------------------------------
FROM golang:1.22-alpine AS build

# distroless/static has no libc, so every invocation must be cgo-free.
ENV CGO_ENABLED=0 \
    GOFLAGS=-trimpath

WORKDIR /src

# Dependency layer. Kept separate so that source edits do not bust the module
# cache. `|| true` tolerates a fresh clone that has not run `go mod tidy` yet.
# Run `make tidy` before the first image build in CI.
COPY go.mod go.sum* ./
RUN go mod download || true

COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY migrations/ ./migrations/

RUN go build -trimpath -ldflags="-s -w" -o /app ./cmd/server

# ---------------------------------------------------------------------------
# Runtime stage
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

# Migrations are embedded into the binary with //go:embed rather than copied,
# because distroless has no shell and no ability to read a bind mount.
COPY --from=build /app /app

USER nonroot:nonroot
EXPOSE 8080

ENTRYPOINT ["/app"]