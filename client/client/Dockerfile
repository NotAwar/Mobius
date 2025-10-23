# Multi-stage build for Mobius Client
FROM golang:1.25.3-alpine AS builder

# Install dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Prepare cached deps
COPY go.work go.work.sum ./
COPY client/client/go.mod ./client/client/
COPY client/client/go.sum ./client/client/
COPY server/api/go.mod ./server/api/
COPY server/api/go.sum ./server/api/
COPY server/cli/go.mod ./server/cli/
COPY server/cli/go.sum ./server/cli/
COPY cocoon/portal/go.mod ./cocoon/portal/
COPY common/shared/go.mod ./common/shared/
COPY common/shared/go.sum ./common/shared/
RUN --mount=type=cache,target=/go/pkg/mod \
	--mount=type=cache,target=/root/.cache/go-build \
	go work sync && \
	(cd client/client && go mod download) && \
	(cd server/api && go mod download) && \
	(cd server/cli && go mod download) && \
	(cd cocoon/portal && go mod download) && \
	(cd common/shared && go mod download)

# Copy sources
COPY . .

# Build the client
WORKDIR /app/client/client
RUN --mount=type=cache,target=/go/pkg/mod \
	--mount=type=cache,target=/root/.cache/go-build \
	CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o client ./cmd/client

# Final stage
FROM alpine:3.20
RUN apk --no-cache add ca-certificates && \
	addgroup -S app && adduser -S -G app app
WORKDIR /app
COPY --from=builder /app/client/client/client /app/client
USER app

# Run the client
ENTRYPOINT ["/app/client"]
