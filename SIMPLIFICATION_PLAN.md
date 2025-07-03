# Mobius Simplification Plan

## Overview
This plan transforms the enterprise Mobius MDM platform into a simplified, single-developer friendly osquery management tool.

## Phase 1: Repository Cleanup (Week 1-2)

### Directories to Remove
- [ ] `website/` - Marketing site (Sails.js)
- [ ] `ansible-mdm/` - Ansible automation
- [ ] `mobiusdaemon-chrome/` - Browser extension
- [ ] `terraform/` - Infrastructure as code
- [ ] `charts/` - Kubernetes/Helm charts
- [ ] `tools/mdm/` - Complex MDM tools
- [ ] `infrastructure/` - Cloud deployment configs
- [ ] `it-and-security/` - Enterprise policies
- [ ] `handbook/` - Documentation
- [ ] `orbit/` - Advanced agent features
- [ ] `security/` - Security policies

### Files to Remove
- [ ] `docker-compose-redis-cluster.yml`
- [ ] `manifest.yml.cloudgov.example`
- [ ] `render.yaml`
- [ ] `setup-ansible-mdm.sh`
- [ ] `osv-scanner.toml`
- [ ] `MODERNIZATION_*.md`

## Phase 2: Backend Simplification (Week 3)

### Server Components to Keep
```
server/
├── cmd/mobius/           # Main application
├── config/               # Configuration
├── datastore/            # Database layer
├── service/              # Core business logic
├── mobius/               # Core models
└── utils.go              # Utilities
```

### Server Components to Remove
- [ ] `server/mdm/` - Mobile device management
- [ ] `server/vulnerabilities/` - Vulnerability scanning
- [ ] `server/sso/` - Single sign-on
- [ ] `server/mail/` - Advanced email features
- [ ] `server/webhooks/` - Webhook integrations
- [ ] `server/worker/` - Background job processing
- [ ] `server/launcher/` - osquery launcher
- [ ] `server/live_query/` - Live query features
- [ ] `server/policies/` - Advanced policy features
- [ ] `server/archtest/` - Architecture testing
- [ ] `server/errorstore/` - Error tracking
- [ ] `server/pubsub/` - Pub/sub messaging

### Configuration Simplification
- [ ] Remove AWS/GCP/Azure configurations
- [ ] Remove SSO configurations (SAML, OIDC)
- [ ] Remove advanced logging (Kafka, Firehose)
- [ ] Remove enterprise features
- [ ] Keep only: MySQL, SMTP, basic auth

## Phase 3: Frontend Simplification (Week 4)

### Frontend Components to Keep
```
frontend/
├── components/
│   ├── forms/           # Form components
│   ├── tables/          # Data tables
│   ├── navigation/      # Navigation
│   └── layout/          # Layout components
├── pages/
│   ├── dashboard/       # Main dashboard
│   ├── hosts/           # Device management
│   ├── queries/         # Query management
│   ├── settings/        # Basic settings
│   └── login/           # Authentication
├── services/            # API clients
└── styles/              # CSS/SCSS
```

### Frontend Components to Remove
- [ ] MDM-specific pages
- [ ] Team management
- [ ] Advanced integrations
- [ ] Vulnerability pages
- [ ] Software deployment
- [ ] Audit logging
- [ ] Advanced reporting
- [ ] Script execution

### Dependencies to Remove
- [ ] Advanced React libraries
- [ ] MDM-specific packages
- [ ] Enterprise integration packages
- [ ] Advanced analytics packages

## Phase 4: Database Simplification (Week 5)

### Core Tables to Keep
- `users` - User accounts
- `hosts` - Managed devices
- `queries` - Saved queries
- `query_results` - Query results
- `sessions` - User sessions
- `app_configs` - Application settings
- `enroll_secrets` - Device enrollment

### Tables to Remove
- [ ] `teams` - Multi-tenancy
- [ ] `vulnerabilities` - Vulnerability data
- [ ] `software` - Software inventory
- [ ] `policies` - Advanced policies
- [ ] `activities` - Audit logs
- [ ] `mdm_*` - MDM-specific tables
- [ ] `integrations` - Third-party integrations
- [ ] `scheduled_queries` - Advanced scheduling

## Phase 5: New Simplified Structure (Week 6)

### Proposed Directory Structure
```
mobius-simple/
├── cmd/
│   └── mobius/          # Main application
├── internal/
│   ├── config/          # Configuration
│   ├── database/        # Database layer
│   ├── handlers/        # HTTP handlers
│   ├── models/          # Data models
│   ├── services/        # Business logic
│   └── auth/            # Authentication
├── web/
│   ├── src/
│   │   ├── components/  # React components
│   │   ├── pages/       # Page components
│   │   ├── services/    # API clients
│   │   └── styles/      # Styling
│   ├── public/
│   └── package.json
├── migrations/          # Database migrations
├── docker-compose.yml   # Development environment
├── Dockerfile          # Container build
├── Makefile            # Build commands
├── go.mod              # Go dependencies
└── README.md           # Documentation
```

### New Features Focus
- **Simple Device Monitoring**: Basic osquery integration
- **Live Queries**: Run queries on connected devices
- **Basic Policies**: Simple configuration management
- **Device Inventory**: Track connected devices
- **User Management**: Simple authentication
- **Dashboard**: Overview of fleet status

### Removed Complexities
- ❌ Multi-tenancy
- ❌ Advanced MDM features
- ❌ Enterprise integrations
- ❌ Complex deployment options
- ❌ Advanced security features
- ❌ Vulnerability scanning
- ❌ Software deployment
- ❌ Audit logging
- ❌ Team management
- ❌ Advanced reporting

## Implementation Steps

### Step 1: Create New Repository
```bash
# Create new simplified repository
git clone /Users/awar/Documents/Mobius mobius-simple
cd mobius-simple
git checkout -b simplification
```

### Step 2: Remove Directories
```bash
# Remove complex components
rm -rf website/ ansible-mdm/ mobiusdaemon-chrome/ terraform/ charts/
rm -rf tools/mdm/ infrastructure/ it-and-security/ handbook/
rm -rf orbit/ security/

# Remove unnecessary files
rm docker-compose-redis-cluster.yml manifest.yml.cloudgov.example
rm render.yaml setup-ansible-mdm.sh osv-scanner.toml
rm MODERNIZATION_*.md
```

### Step 3: Simplify Go Dependencies
```bash
# Remove enterprise packages from go.mod
# Keep only: database, HTTP, basic auth, osquery
```

### Step 4: Simplify Frontend Dependencies
```bash
# Remove from package.json:
# - Storybook
# - Advanced testing tools
# - MDM-specific packages
# - Enterprise integration packages
```

### Step 5: Create New Documentation
- [ ] Simple README with quick start
- [ ] Basic configuration guide
- [ ] Development setup instructions
- [ ] API documentation (simplified)

## Benefits of Simplification

1. **Reduced Complexity**: 90% fewer files and dependencies
2. **Faster Development**: Simpler build and test processes
3. **Easier Maintenance**: Focused feature set
4. **Better Performance**: Removed unnecessary overhead
5. **Clear Purpose**: Device monitoring and management
6. **Single Developer Friendly**: No enterprise complexity

## Timeline
- **Week 1-2**: Directory cleanup and removal
- **Week 3**: Backend simplification
- **Week 4**: Frontend simplification
- **Week 5**: Database simplification
- **Week 6**: New structure and documentation

## Success Metrics
- [ ] Repository size reduced by 80%+
- [ ] Build time under 2 minutes
- [ ] Development setup in under 5 minutes
- [ ] Core functionality working
- [ ] Clear documentation
- [ ] Single command deployment
