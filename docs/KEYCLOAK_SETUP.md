# Keycloak Setup Guide

This guide explains how to deploy and configure Keycloak for Mobius authentication.

## Quick Start

### 1. Deploy Keycloak to Kubernetes

```bash
# Apply the Keycloak deployment
kubectl apply -f deployments/keycloak/keycloak.yaml

# Wait for Keycloak to be ready
kubectl wait --for=condition=ready pod -l app=keycloak -n keycloak --timeout=300s

# Check the status
kubectl get pods -n keycloak
```

### 2. Access Keycloak Admin Console

```bash
# Port forward to access locally
kubectl port-forward -n keycloak svc/keycloak 8080:8080

# Open in browser
open http://localhost:8080
```

**Default Admin Credentials:**

- Username: `admin`
- Password: `ChangeMe123!` (⚠️ Change immediately in production!)

### 3. Verify Realm Import

The `mobius` realm should be automatically imported with:

- ✅ Client: `mobius-api` (backend API)
- ✅ Client: `mobius-web` (web UI)
- ✅ Roles: `admin`, `operator`, `viewer`, `user`
- ✅ Test users: `admin`, `operator`, `viewer`

### 4. Update Mobius Server Configuration

Add these environment variables to your Mobius server:

```bash
export KEYCLOAK_REALM_URL="http://keycloak.keycloak.svc.cluster.local:8080/realms/mobius"
export KEYCLOAK_CLIENT_ID="mobius-api"
export KEYCLOAK_CLIENT_SECRET="mobius-api-secret-change-me"
export KEYCLOAK_ENABLED="true"
```

For local development:

```bash
export KEYCLOAK_REALM_URL="http://localhost:8080/realms/mobius"
export KEYCLOAK_CLIENT_ID="mobius-api"
export KEYCLOAK_CLIENT_SECRET="mobius-api-secret-change-me"
export KEYCLOAK_ENABLED="true"
```

---

## Detailed Configuration

### Realm Structure

The `mobius` realm includes:

**Clients:**

1. **mobius-api** (Confidential)
   - Used by backend API for token validation
   - Client secret: `mobius-api-secret-change-me`
   - Supports: Authorization Code Flow, Resource Owner Password Flow
   - Service accounts enabled

2. **mobius-web** (Public)
   - Used by web UI for user authentication
   - No client secret (public client)
   - Supports: Authorization Code Flow with PKCE

**Roles:**

1. **admin** - Full administrative access
   - Can: Create/update/delete all resources
   - Can: Manage users and permissions
   - Can: Access all API endpoints

2. **operator** - Operations access
   - Can: Manage clients (create, update, delete)
   - Can: Execute OSQuery queries
   - Can: View and execute commands
   - Cannot: Manage users or system configuration

3. **viewer** - Read-only access
   - Can: View all resources
   - Cannot: Modify anything

4. **user** - Basic access
   - Can: View own resources
   - Cannot: Access management features

**Default Users:**

- **admin** / `admin123` - Admin role
- **operator** / `operator123` - Operator role
- **viewer** / `viewer123` - Viewer role

⚠️ **Change these passwords immediately in production!**

---

## Testing Authentication

### 1. Get an Access Token

```bash
# Using password flow (for testing)
curl -X POST "http://localhost:8080/realms/mobius/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=mobius-api" \
  -d "client_secret=mobius-api-secret-change-me" \
  -d "username=admin" \
  -d "password=admin123" \
  -d "scope=openid profile email" | jq -r .access_token
```

Save the token:

```bash
TOKEN=$(curl -X POST "http://localhost:8080/realms/mobius/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=mobius-api" \
  -d "client_secret=mobius-api-secret-change-me" \
  -d "username=admin" \
  -d "password=admin123" | jq -r .access_token)
```

### 2. Call Protected API Endpoint

```bash
# Test with admin user (should work for all endpoints)
curl -H "Authorization: Bearer $TOKEN" http://localhost:3001/api/v1/users

# Test with operator user
TOKEN_OP=$(curl -X POST "http://localhost:8080/realms/mobius/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=mobius-api" \
  -d "client_secret=mobius-api-secret-change-me" \
  -d "username=operator" \
  -d "password=operator123" | jq -r .access_token)

curl -H "Authorization: Bearer $TOKEN_OP" http://localhost:3001/api/v1/clients

# Test with viewer user (read-only)
TOKEN_VIEW=$(curl -X POST "http://localhost:8080/realms/mobius/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=mobius-api" \
  -d "client_secret=mobius-api-secret-change-me" \
  -d "username=viewer" \
  -d "password=viewer123" | jq -r .access_token)

curl -H "Authorization: Bearer $TOKEN_VIEW" http://localhost:3001/api/v1/clients
```

### 3. Verify Token Claims

```bash
# Decode JWT token (using jwt.io or jq)
echo $TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .

# Should include:
# - "preferred_username": "admin"
# - "email": "admin@mobius.local"
# - "roles": ["admin"]
```

---

## Production Configuration

### 1. Change Default Passwords

```bash
kubectl exec -n keycloak keycloak-0 -- \
  /opt/keycloak/bin/kcadm.sh config credentials \
  --server http://localhost:8080 \
  --realm master \
  --user admin \
  --password ChangeMe123!

# Change admin password
kubectl exec -n keycloak keycloak-0 -- \
  /opt/keycloak/bin/kcadm.sh set-password \
  --server http://localhost:8080 \
  --realm master \
  --username admin \
  --new-password "YOUR_STRONG_PASSWORD"
```

### 2. Rotate Client Secrets

1. Log into Keycloak admin console
2. Navigate to: `Mobius realm` → `Clients` → `mobius-api`
3. Go to `Credentials` tab
4. Click `Regenerate Secret`
5. Copy the new secret
6. Update Mobius server environment variable: `KEYCLOAK_CLIENT_SECRET`

### 3. Configure TLS/HTTPS

For production, enable HTTPS:

```yaml
# Update keycloak.yaml
env:
  - name: KC_HOSTNAME
    value: "keycloak.yourdomain.com"
  - name: KC_HOSTNAME_STRICT
    value: "true"
  - name: KC_HOSTNAME_STRICT_HTTPS
    value: "true"
  - name: KC_HTTPS_CERTIFICATE_FILE
    value: "/etc/x509/https/tls.crt"
  - name: KC_HTTPS_CERTIFICATE_KEY_FILE
    value: "/etc/x509/https/tls.key"
```

### 4. Enable Database Persistence

For production, use PostgreSQL instead of H2:

```yaml
env:
  - name: KC_DB
    value: "postgres"
  - name: KC_DB_URL
    value: "jdbc:postgresql://postgres:5432/keycloak"
  - name: KC_DB_USERNAME
    valueFrom:
      secretKeyRef:
        name: keycloak-db
        key: username
  - name: KC_DB_PASSWORD
    valueFrom:
      secretKeyRef:
        name: keycloak-db
        key: password
```

### 5. Configure Identity Providers

#### Azure Active Directory

1. Log into Keycloak admin console
2. Navigate to: `Mobius realm` → `Identity Providers`
3. Click `Add provider` → `Azure`
4. Configure:
   - **Alias**: `azure`
   - **Client ID**: From Azure AD app registration
   - **Client Secret**: From Azure AD app registration
   - **Authorization URL**: `https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/authorize`
   - **Token URL**: `https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/token`

#### Google Workspace

1. Add provider → `Google`
2. Configure:
   - **Client ID**: From Google Cloud Console
   - **Client Secret**: From Google Cloud Console

#### GitHub

1. Add provider → `GitHub`
2. Configure:
   - **Client ID**: From GitHub OAuth App
   - **Client Secret**: From GitHub OAuth App

---

## Troubleshooting

### Keycloak pod not starting

```bash
# Check logs
kubectl logs -n keycloak keycloak-0

# Common issues:
# - Out of memory: Increase resource limits
# - Port conflicts: Check if port 8080 is in use
# - Realm import failed: Check ConfigMap syntax
```

### Token validation failing

```bash
# Verify Keycloak is accessible from server
kubectl exec -it <mobius-server-pod> -- \
  curl http://keycloak.keycloak.svc.cluster.local:8080/realms/mobius

# Check KEYCLOAK_REALM_URL matches the accessible URL
env | grep KEYCLOAK
```

### Permission denied errors

```bash
# Verify token has correct roles
echo $TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .roles

# Check user role assignments in Keycloak admin console
# Mobius realm → Users → [username] → Role mapping
```

### Realm not imported

```bash
# Manually import realm
kubectl cp deployments/keycloak/realm-mobius.json keycloak-0:/tmp/realm.json -n keycloak

kubectl exec -n keycloak keycloak-0 -- \
  /opt/keycloak/bin/kc.sh import \
  --file /tmp/realm.json
```

---

## API Integration

### Middleware Configuration

The Keycloak middleware in `api/v1/auth.go` validates JWT tokens:

```go
// Enable Keycloak authentication
os.Setenv("KEYCLOAK_ENABLED", "true")
os.Setenv("KEYCLOAK_REALM_URL", "http://keycloak:8080/realms/mobius")
os.Setenv("KEYCLOAK_CLIENT_ID", "mobius-api")
os.Setenv("KEYCLOAK_CLIENT_SECRET", "mobius-api-secret-change-me")
```

### Protected Routes

All API routes are protected by default. Public routes:

- `GET /api/v1/health`
- `POST /api/v1/clients/enroll` (uses enrollment key)
- `POST /api/v1/clients/:id/check-in` (uses client key)

### RBAC Permissions

See `api/v1/auth.go` for full permission matrix:

| Endpoint | Admin | Operator | Viewer | User |
|----------|-------|----------|--------|------|
| GET /users | ✅ | ❌ | ✅ | ❌ |
| POST /users | ✅ | ❌ | ❌ | ❌ |
| GET /clients | ✅ | ✅ | ✅ | ❌ |
| POST /clients | ✅ | ✅ | ❌ | ❌ |
| DELETE /clients | ✅ | ✅ | ❌ | ❌ |
| POST /osquery/execute | ✅ | ✅ | ❌ | ❌ |
| GET /audit/logs | ✅ | ❌ | ✅ | ❌ |

---

## Web UI Integration

### Login Flow

1. User visits `http://localhost:3000`
2. If not authenticated, redirect to Keycloak:

   ```
   http://localhost:8080/realms/mobius/protocol/openid-connect/auth?
     client_id=mobius-web&
     redirect_uri=http://localhost:3000/callback&
     response_type=code&
     scope=openid profile email
   ```

3. User logs in with Keycloak
4. Keycloak redirects back with authorization code
5. Web app exchanges code for tokens
6. Store access token in localStorage/sessionStorage
7. Include token in all API requests:

   ```javascript
   headers: {
     'Authorization': `Bearer ${accessToken}`
   }
   ```

### Token Refresh

```javascript
// Refresh token before expiry
async function refreshToken(refreshToken) {
  const response = await fetch(
    'http://localhost:8080/realms/mobius/protocol/openid-connect/token',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: 'mobius-web',
        refresh_token: refreshToken
      })
    }
  );
  return response.json();
}
```

---

## References

- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [OpenID Connect Specification](https://openid.net/connect/)
- [OAuth 2.0 Specification](https://oauth.net/2/)
- [JWT.io](https://jwt.io/) - Decode and verify JWT tokens

---

**Last Updated:** December 18, 2025
