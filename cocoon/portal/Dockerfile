# Multi-stage build for Mobius Cocoon
FROM golang:1.25.3-alpine AS builder

# Install dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Prepare cached deps
COPY go.work go.work.sum ./
COPY cocoon/portal/go.mod ./cocoon/portal/
COPY server/api/go.mod ./server/api/
COPY server/api/go.sum ./server/api/
COPY server/cli/go.mod ./server/cli/
COPY server/cli/go.sum ./server/cli/
COPY client/client/go.mod ./client/client/
COPY client/client/go.sum ./client/client/
COPY common/shared/go.mod ./common/shared/
COPY common/shared/go.sum ./common/shared/
RUN --mount=type=cache,target=/go/pkg/mod \
	--mount=type=cache,target=/root/.cache/go-build \
	go work sync && \
	(cd cocoon/portal && go mod download) && \
	(cd server/api && go mod download) && \
	(cd server/cli && go mod download) && \
	(cd client/client && go mod download) && \
	(cd common/shared && go mod download)

# Copy sources
COPY . .

# Build the cocoon
WORKDIR /app/cocoon/portal
RUN --mount=type=cache,target=/go/pkg/mod \
	--mount=type=cache,target=/root/.cache/go-build \
	CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o cocoon ./cmd/cocoon

# Final stage
FROM alpine:3.20
RUN apk --no-cache add ca-certificates && \
	addgroup -S app && adduser -S -G app app
WORKDIR /app
COPY --from=builder /app/cocoon/portal/cocoon /app/cocoon
USER app

# Expose the cocoon port
EXPOSE 8082

# Run the cocoon
ENTRYPOINT ["/app/cocoon"]
ENTRYPOINT ["/app/cocoon"]
