# Multi-stage build for React frontend
FROM node:24-alpine AS builder

# Install yarn
RUN apk add --no-cache yarn

WORKDIR /app

# Copy package files from root directory
COPY package.json ./

# Install dependencies (will generate yarn.lock)
RUN yarn install

# Copy source code from frontend directory
COPY frontend/ ./frontend/

# Copy webpack config and other build files
COPY webpack.config.js ./
COPY tsconfig.json ./
COPY babel.config.json ./
COPY postcss.config.js ./
COPY .eslintrc.js ./

# Build the application
RUN yarn build

# Production stage
FROM nginx:alpine

# Copy built assets from builder stage
COPY --from=builder /app/assets /usr/share/nginx/html

# Copy nginx configuration from frontend directory
COPY frontend/nginx.conf /etc/nginx/nginx.conf

# Expose port 80
EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]