# Multi-stage build for Mobius API Server
# Go builder stage
FROM golang:1.25.3-alpine AS builder

# Install dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Leverage Go build cache: copy workspace files first
COPY go.work go.work.sum ./
COPY server/api/go.mod ./server/api/
COPY server/api/go.sum ./server/api/
COPY server/cli/go.mod ./server/cli/
COPY server/cli/go.sum ./server/cli/
COPY client/client/go.mod ./client/client/
COPY client/client/go.sum ./client/client/
COPY cocoon/portal/go.mod ./cocoon/portal/
COPY common/shared/go.mod ./common/shared/
COPY common/shared/go.sum ./common/shared/

# Download deps (cached)
RUN --mount=type=cache,target=/go/pkg/mod \
	--mount=type=cache,target=/root/.cache/go-build \
	go work sync && \
	(cd server/api && go mod download) && \
	(cd server/cli && go mod download) && \
	(cd client/client && go mod download) && \
	(cd cocoon/portal && go mod download) && \
	(cd common/shared && go mod download)

# Copy the full sources
COPY . .

# Build the server (frontend static files should already be in ./static/ from CI build)
WORKDIR /app/server/api
RUN --mount=type=cache,target=/go/pkg/mod \
	--mount=type=cache,target=/root/.cache/go-build \
	CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o mobius-api ./cmd/api-server/main.go

# Final stage
FROM alpine:3.20

# Add non-root user and CA certs
RUN apk --no-cache add ca-certificates && \
	addgroup -S app && adduser -S -G app app

WORKDIR /app

# Copy the binary
COPY --from=builder /app/server/api/mobius-api /app/mobius-api
USER app

# Expose port 8081 (API server default)
EXPOSE 8081

# Run the server
ENTRYPOINT ["/app/mobius-api"]
