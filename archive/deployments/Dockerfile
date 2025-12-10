# Multi-stage build for Mobius with Svelte UI
# Node.js stage for frontend build
FROM node:24-alpine AS frontend-builder

WORKDIR /app/frontend

# Copy frontend package files
COPY ui/web/package*.json ./
COPY ui/web/vite.config.ts ./
COPY ui/web/svelte.config.js ./
COPY ui/web/tsconfig.json ./

# Install frontend dependencies
RUN npm ci --omit=dev

# Copy frontend source code
COPY ui/web/src ./src
COPY ui/web/static ./static

# Build the frontend
RUN npm run build

# Go builder stage
FROM golang:1.25.3-alpine AS builder

# Install git and ca-certificates
RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy go workspace files
COPY go.work go.work.sum ./

# Copy module files (copy go.sum only if it exists)
COPY server/api/go.mod ./server/api/
COPY server/api/go.sum ./server/api/
COPY server/cli/go.mod ./server/cli/
COPY server/cli/go.sum ./server/cli/
COPY client/client/go.mod ./client/client/
COPY client/client/go.sum ./client/client/
COPY cocoon/portal/go.mod ./cocoon/portal/
COPY common/shared/go.mod ./common/shared/
COPY common/shared/go.sum ./common/shared/

# Download dependencies
WORKDIR /app
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go work sync
WORKDIR /app/server/api
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

# Back to app directory
WORKDIR /app

# Copy source code
COPY server/api/ ./server/api/
COPY server/cli/ ./server/cli/
COPY client/client/ ./client/client/
COPY cocoon/portal/ ./cocoon/portal/
COPY common/shared/ ./common/shared/

# Copy frontend build output to static directory
COPY --from=frontend-builder /app/frontend/build ./server/api/static/

# Build the application
WORKDIR /app/server/api
# BuildKit platform variables for multi-platform builds
ARG TARGETOS
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -a -installsuffix cgo -o mobius-api cmd/api-server/main.go

# Production stage
FROM alpine:3.22

# Install ca-certificates for HTTPS and add non-root user
RUN apk --no-cache add ca-certificates && \
    addgroup -S app && adduser -S -G app app

# Create non-root user for security
RUN addgroup -g 1001 -S mobius && \
    adduser -S -D -H -u 1001 -G mobius mobius


WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/server/api/mobius-api ./mobius-api


# Make binary executable and owned by mobius user
RUN chmod +x ./mobius-api && chown mobius:mobius ./mobius-api

# Switch to non-root user
USER mobius

# Expose port 8081 (API server default)
EXPOSE 8081


# Run the application
CMD ["./mobius-api"]