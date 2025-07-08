# Multi-stage build for Go backend
FROM golang:1.24-alpine AS builder

# Install git, ca-certificates, and nodejs/yarn for frontend build
RUN apk add --no-cache git ca-certificates nodejs yarn

WORKDIR /app

# Copy package files and install JS dependencies
COPY package.json ./
RUN yarn install

# Copy configuration files
COPY webpack.config.js ./
COPY tsconfig.json ./
COPY babel.config.json ./
COPY postcss.config.js ./
COPY .eslintrc.js ./

# Copy frontend source code
COPY frontend/ ./frontend/

# Build frontend assets
RUN NODE_ENV=production yarn run webpack --progress

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Generate embedded assets and build the application
RUN go run github.com/kevinburke/go-bindata/go-bindata -pkg=bindata -tags full \
    -o=server/bindata/generated.go \
    frontend/templates/ assets/... server/mail/templates

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o mobius ./cmd/mobius

# Production stage
FROM alpine:latest

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the binary from builder stage
COPY --from=builder /app/mobius .

# Expose port 8080
EXPOSE 8080

# Run the application
CMD ["./mobius"]