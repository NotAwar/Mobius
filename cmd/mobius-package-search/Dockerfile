# Stage 1: Build the Go binary
FROM docker.io/library/golang:1.25.3-alpine AS builder

WORKDIR /app

COPY go.mod .
RUN go mod download

COPY . .
RUN go mod tidy

RUN chmod +x internal/apt-search.sh internal/flatpak-search.sh

RUN go build -o search-api .

# Stage 2: Lightweight Ubuntu runtime
FROM docker.io/library/ubuntu:rolling

ENV DEBIAN_FRONTEND=noninteractive

# Install only essential packages
RUN apt-get update && apt-get install -y --no-install-recommends \
  flatpak \
  software-properties-common \
  ca-certificates \
  curl \
  bash \
  && apt clean && rm -rf /var/lib/apt/lists/*

# Set up Flathub
RUN flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo

WORKDIR /app

COPY --from=builder /app/search-api .
COPY --from=builder /app/internal ./internal

EXPOSE 8080

CMD ["./search-api"]
