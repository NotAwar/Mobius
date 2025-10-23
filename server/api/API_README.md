# Mobius MDM API Server

The new Mobius Mobile Device Management API server provides a clean, RESTful interface for managing devices, policies, applications, and user authentication in a self-hosted environment.

## Quick Start

### Build and Run

```bash
# Build the API server
go build -o mobius-api ./cmd/api-server/

# Run the server
./mobius-api
```

The server will start on `http://localhost:8081` by default.

### Default Credentials

- **Email**: `admin@mobius.local`
- **Password**: `admin123`

## API Endpoints

### Authentication

#### Login
```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "admin@mobius.local",
  "password": "admin123"
}
```

Response:
```json
{
  "token": "token_admin-1_1629384000",
  "expires_at": "2024-08-13T16:19:56Z",
  "user": {
    "id": "admin-1",
    "email": "admin@mobius.local",
    "name": "Administrator",
    "role": "admin",
    "created_at": "2024-08-12T16:19:56Z",
    "updated_at": "2024-08-12T16:19:56Z"
  }
}
```

### System Health

#### Health Check
```http
GET /api/v1/health
```

Response:
```json
{
  "status": "healthy",
  "timestamp": "2024-08-12T16:19:56Z",
  "version": "1.0.0",
  "components": {
    "database": {"status": "up", "message": "Connected"},
    "cache": {"status": "up", "message": "Redis operational"},
    "storage": {"status": "up", "message": "File system accessible"}
  }
}
```

#### Metrics (Prometheus format)
```http
GET /api/v1/metrics
```

### License Management

#### Get License Status
```http
GET /api/v1/license/status
Authorization: Bearer <token>
```

Response:
```json
{
  "valid": true,
  "tier": "community",
  "device_limit": 10,
  "devices_enrolled": 0,
  "expires_at": null,
  "features": [
    "device_management",
    "basic_policies"
  ]
}
```

#### Update License (Admin Only)
```http
PUT /api/v1/license
Authorization: Bearer <token>
Content-Type: application/json

{
  "key": "professional-license"
}
```

### Device Management

#### List Devices
```http
GET /api/v1/devices?limit=50&offset=0&platform=windows&status=online
Authorization: Bearer <token>
```

#### Enroll Device
```http
POST /api/v1/devices
Authorization: Bearer <token>
Content-Type: application/json

{
  "uuid": "device-uuid-123",
  "hostname": "workstation-01",
  "platform": "windows",
  "os_version": "Windows 11 Pro",
  "enrollment_secret": "secret-key"
}
```

#### Get Device Details
```http
GET /api/v1/devices/{deviceId}
Authorization: Bearer <token>
```

#### Unenroll Device
```http
DELETE /api/v1/devices/{deviceId}
Authorization: Bearer <token>
```

### Policy Management

#### List Policies
```http
GET /api/v1/policies
Authorization: Bearer <token>
```

#### Create Policy
```http
POST /api/v1/policies
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "Security Policy",
  "description": "Basic security requirements",
  "platform": "all",
  "configuration": {
    "require_encryption": true,
    "password_complexity": "high",
    "auto_lock_timeout": 300
  }
}
```

#### Update Policy
```http
PUT /api/v1/policies/{policyId}
Authorization: Bearer <token>
Content-Type: application/json

{
  "enabled": false,
  "configuration": {
    "auto_lock_timeout": 600
  }
}
```

### Application Management

#### List Applications
```http
GET /api/v1/applications
Authorization: Bearer <token>
```

#### Add Application
```http
POST /api/v1/applications
Authorization: Bearer <token>
Content-Type: multipart/form-data

name: "Chrome Browser"
version: "91.0.4472.124"
platform: "windows"
package: <binary-file>
```

### Device API (For Client Connections)

#### Device Check-in
```http
POST /api/v1/device/checkin
Authorization: Bearer <device-token>
Content-Type: application/json

{
  "os_version": "Windows 11 Pro 22000.1",
  "system_info": {
    "cpu": "Intel Core i7",
    "memory": "16GB"
  },
  "query_results": {
    "installed_software": [...]
  }
}
```

#### Get Device Policies
```http
GET /api/v1/device/policies
Authorization: Bearer <device-token>
```

#### Get Device Applications
```http
GET /api/v1/device/applications
Authorization: Bearer <device-token>
```

## Architecture

### Clean Architecture

The API follows clean architecture principles with clear separation of concerns:

```
/api/
  ├── router.go      # HTTP routing and middleware setup
  ├── handlers.go    # HTTP request handlers
  ├── middleware.go  # HTTP middleware (auth, logging, CORS)
  └── openapi.yaml   # API specification

/pkg/service/
  └── services.go    # Business logic implementations

/cmd/api-server/
  └── main.go        # Application entry point
```

### Key Features

- **RESTful API Design**: Clean, predictable endpoints following REST conventions
- **JWT Authentication**: Secure token-based authentication for users and devices
- **Role-Based Access Control**: Admin, operator, and viewer roles with appropriate permissions
- **License Management**: Built-in licensing system with community, professional, and enterprise tiers
- **Graceful Shutdown**: Proper handling of shutdown signals with connection draining
- **Structured Logging**: JSON-formatted logs with request tracing
- **Health Monitoring**: Health checks and Prometheus metrics for observability
- **Security Headers**: CORS, CSP, and other security headers configured
- **Rate Limiting**: Built-in rate limiting to prevent abuse

### License Tiers

1. **Community** (Free)
   - Up to 10 devices
   - Basic device management
   - Simple policies
   - Never expires

2. **Professional** ($99/year)
   - Up to 100 devices
   - Advanced policies
   - Application management
   - Reporting features

3. **Enterprise** (Contact Sales)
   - Unlimited devices
   - All features
   - Integrations
   - Custom scripts
   - Priority support

### Security Considerations

- All API endpoints (except health and login) require authentication
- Admin-only endpoints are properly protected
- Device tokens are separate from user tokens
- Rate limiting prevents brute force attacks
- Security headers protect against common web vulnerabilities
- HTTPS should be used in production (configure with TLS certificates)

### Development

#### Adding New Endpoints

1. Define the endpoint in `openapi.yaml`
2. Add the route in `router.go`
3. Implement the handler in `handlers.go`
4. Add business logic to appropriate service in `pkg/service/`
5. Update this documentation

#### Testing

```bash
# Health check
curl http://localhost:8081/api/v1/health

# Login
curl -X POST http://localhost:8081/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@mobius.local","password":"admin123"}'

# Get license status (with token from login)
curl http://localhost:8081/api/v1/license/status \
  -H "Authorization: Bearer <token>"
```

### Next Steps

This API server provides the foundation for the Mobius MDM platform. Key areas for development:

1. **Database Integration**: Replace in-memory storage with PostgreSQL/MySQL
2. **Device Enrollment**: Implement certificate-based device enrollment
3. **Policy Engine**: Build the policy evaluation and enforcement system
4. **Application Distribution**: Add secure application packaging and distribution
5. **OSQuery Integration**: Implement device querying and data collection
6. **Web Dashboard**: Build React frontend for administration
7. **Mobile Clients**: Develop iOS/Android MDM clients
8. **Enterprise Features**: SAML SSO, SCIM provisioning, audit logging

### Contributing

When making changes to the API:

1. Update the OpenAPI specification first
2. Implement the endpoint with proper error handling
3. Add appropriate logging and metrics
4. Update documentation
5. Test with various scenarios including error cases
