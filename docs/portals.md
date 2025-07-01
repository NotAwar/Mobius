# Mobius MDM Portal System

The Mobius MDM platform provides three distinct portal interfaces to serve different user needs and administrative requirements:

## Portal Overview

### 1. Main Dashboard
**Path:** `/dashboard`  
**Access:** All authenticated users  
**Purpose:** Primary administrative interface for device management

**Features:**
- Device inventory and monitoring
- Policy management and enforcement
- Software distribution and updates
- Query and reporting capabilities
- Security compliance monitoring
- Ansible MDM configuration interface

### 2. Internal Admin Portal
**Path:** `/internal-portal`  
**Access:** Global administrators only  
**Purpose:** Advanced system administration and configuration

**Features:**
- System health monitoring and statistics
- User and team management
- Advanced Ansible MDM configuration
- System audit logs and activity tracking
- Internal system troubleshooting tools
- Backend service configuration

### 3. User Portal
**Path:** `/user-portal`  
**Access:** All authenticated users  
**Purpose:** Self-service interface for end users

**Features:**
- Personal device enrollment and management
- Device status monitoring
- Support request submission
- Profile management
- Download enrollment profiles
- Access to user documentation

### 4. Portal Navigation Hub
**Path:** `/portals`  
**Access:** All authenticated users  
**Purpose:** Central navigation point between different portals

## Portal Architecture

### Frontend Components

```
frontend/
├── pages/
│   ├── InternalPortal/
│   │   ├── InternalPortal.tsx
│   │   ├── InternalPortal.scss
│   │   └── index.ts
│   ├── UserPortal/
│   │   ├── UserPortal.tsx
│   │   ├── UserPortal.scss
│   │   └── index.ts
│   └── PortalPage/
│       ├── PortalPage.tsx
│       └── index.ts
├── components/
│   └── PortalNavigation/
│       ├── PortalNavigation.tsx
│       ├── PortalNavigation.scss
│       └── index.ts
└── services/
    └── entities/
        └── portals.ts
```

### Backend API Endpoints

```
/api/latest/mobius/internal-portal/stats      - GET: System statistics
/api/latest/mobius/internal-portal/logs       - GET: System activity logs
/api/latest/mobius/user-portal/devices        - GET: User's devices
/api/latest/mobius/user-portal/enrollment     - POST: Generate enrollment code
/api/latest/mobius/user-portal/profile        - GET: Download enrollment profile
/api/latest/mobius/user-portal/support        - POST: Submit support request
/api/latest/mobius/portal/user/:id            - GET/PATCH: Portal user data
```

### Authentication and Authorization

- **Main Dashboard:** Requires authentication, role-based access to features
- **Internal Admin Portal:** Requires global admin privileges
- **User Portal:** Requires authentication, users can only access their own data
- **Portal Navigation:** Dynamically shows available portals based on user permissions

## Usage Examples

### Accessing Portals

1. **Direct Portal Access:**
   ```
   https://mobius.example.com/internal-portal  # Admin only
   https://mobius.example.com/user-portal      # All users
   https://mobius.example.com/dashboard        # Primary interface
   ```

2. **Portal Navigation Hub:**
   ```
   https://mobius.example.com/portals          # Central navigation
   ```

### User Experience Flow

1. **Admin Users:**
   - Login → Dashboard (default)
   - Access `/portals` for navigation between interfaces
   - Use Internal Portal for system administration
   - Use Dashboard for device management

2. **End Users:**
   - Login → Dashboard (default) 
   - Access User Portal for self-service device management
   - Enroll personal devices using generated enrollment codes
   - Submit support requests through User Portal

### Device Enrollment via User Portal

1. User accesses User Portal (`/user-portal`)
2. Clicks "Generate Enrollment Instructions"
3. Receives unique enrollment code and platform-specific profiles
4. Downloads appropriate enrollment profile for their device
5. Installs profile and uses enrollment code during setup
6. Device appears in their "My Devices" section

## Configuration

### Environment Variables

```bash
# Portal feature flags
MOBIUS_ENABLE_USER_PORTAL=true
MOBIUS_ENABLE_INTERNAL_PORTAL=true
MOBIUS_PORTAL_SUPPORT_EMAIL=support@example.com

# Enrollment settings
MOBIUS_USER_ENROLLMENT_ENABLED=true
MOBIUS_ENROLLMENT_CODE_EXPIRY=24h
```

### Frontend Configuration

The portal system integrates with the existing Mobius configuration:

```typescript
interface IConfig {
  features: {
    enable_user_portal: boolean;
    enable_internal_portal: boolean;
  };
  portal_settings: {
    support_email: string;
    enrollment_enabled: boolean;
  };
}
```

## Security Considerations

1. **Access Control:** Each portal enforces appropriate role-based access
2. **Data Isolation:** Users can only access their own devices in User Portal
3. **Audit Logging:** All portal activities are logged for audit purposes
4. **Enrollment Security:** Enrollment codes are time-limited and user-specific
5. **API Authentication:** All API endpoints require valid authentication tokens

## Development

### Adding New Portal Features

1. **Frontend:**
   - Add new components to appropriate portal page
   - Update service API calls in `services/entities/portals.ts`
   - Add new routes if needed in `router/paths.ts`

2. **Backend:**
   - Add new endpoints to `server/service/portals.go`
   - Update endpoint constants in `frontend/utilities/endpoints.ts`
   - Implement proper authorization checks

3. **Navigation:**
   - Update `PortalNavigation` component to include new features
   - Add feature flags for conditional display

### Testing

```bash
# Frontend tests
npm test -- --testPathPattern=Portal

# Backend tests
go test ./server/service/... -run Portal

# E2E tests
npm run cypress:run -- --spec="**/portals.spec.ts"
```

## Troubleshooting

### Common Issues

1. **Portal Access Denied:**
   - Check user roles and permissions
   - Verify authentication token validity
   - Review audit logs for access attempts

2. **Enrollment Failures:**
   - Verify enrollment codes haven't expired
   - Check device platform compatibility
   - Review enrollment profile configuration

3. **API Errors:**
   - Check backend service health
   - Verify database connectivity
   - Review application logs

### Monitoring

- Portal usage metrics available in Internal Portal
- API endpoint monitoring via standard Mobius monitoring
- User enrollment success rates tracked in system logs

---

This portal system provides a comprehensive interface structure for Mobius MDM, separating administrative, user-facing, and internal system management concerns while maintaining a unified authentication and authorization system.
