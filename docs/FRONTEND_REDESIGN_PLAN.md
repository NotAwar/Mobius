# Frontend Redesign Plan - MDM-First Approach

## Issues Identified ✅

### 1. **File Management Problems**

- ✅ **FIXED**: Removed all `.new` and `.backup` duplicate files
- ✅ **FIXED**: Single source of truth for each route
- Files cleaned up:
  - `+page.svelte.backup` - REMOVED
  - `cluster/+page.svelte.new` - REMOVED  
  - `headscale/+page.svelte.new` - REMOVED
  - `postgres/+page.svelte.new` - REMOVED

### 2. **Emoji Usage**

- ✅ **FIXED**: Removed ALL emojis from navigation
- ✅ **FIXED**: Replaced with proper SVG icons or removed entirely
- Old: `{ href: '/', label: 'Dashboard', icon: '📊' }`
- New: Clean text-only or SVG icons

### 3. **Color Scheme Issues**

- ✅ **FIXED**: Removed blue-purple gradient (`from-purple-600 via-blue-600 to-indigo-600`)
- ✅ **FIXED**: Applied proper branding colors from `theme.json`:
  - Primary: `#1c2f38` (dark teal)
  - Secondary: `#31413e` (darker teal)
  - Accent: `#d4af37` (gold)
  - Success: `#4ade80` (green)
  - Error: `#ef4444` (red)
  - Warning: `#fbbf24` (yellow)

### 4. **Asset Integration**

- ✅ **FIXED**: Added Mobius logo to sidebar: `/assets/Mobius_Logo.png`
- ✅ **FIXED**: Added logo with text to dashboard: `/assets/Mobius-Logo-Text_1.png`
- ⏳ **TODO**: Create 404 error page using `/assets/ERROR-404.png`
- ⏳ **TODO**: Create generic error page using `/assets/ERROR-generic.png`
- ⏳ **TODO**: Add favicon references

### 5. **MDM-First Design**

- ✅ **FIXED**: Reorganized navigation into MDM-focused sections:
  - **Device Management** (primary focus)
    - Dashboard
    - Clients
    - Client Groups
    - Enrollment
  - **Monitoring**
    - OSQuery
    - Queries
    - Health Status
  - **Administration**
    - Users & Roles
    - Audit Logs
    - Settings
  - **Infrastructure** (secondary/backend)
    - Kubernetes
    - Database
    - VPN

### 6. **Navigation Structure**

- ✅ **FIXED**: Added proper sectioning with headers
- ✅ **FIXED**: Grouped related functionality
- ✅ **FIXED**: Moved infrastructure items to bottom (de-emphasized)

### 7. **Dashboard Improvements**

- ✅ **FIXED**: Created MDM-focused dashboard showing:
  - Total Clients stat card
  - Online Clients stat card
  - Offline Clients stat card
  - Client Groups stat card
  - System Health indicator
  - Quick Actions (Add Client, Manage Groups, Run Query, View Logs)
  - Recently Active Clients table

## Completed Work ✅

### Layout Component (`/web/src/routes/+layout.svelte`)

- ✅ Removed all emojis from navigation
- ✅ Applied proper branding colors (#1c2f38, #31413e, #d4af37)
- ✅ Integrated Mobius logo image
- ✅ Organized navigation into 4 sections with headings
- ✅ MDM-first ordering (Device Management → Monitoring → Administration → Infrastructure)
- ✅ Fixed active state colors (gold accent)
- ✅ Added proper fonts (Montserrat for headings, Ubuntu for body)

### Dashboard Page (`/web/src/routes/+page.svelte`)

- ✅ Created MDM-focused dashboard
- ✅ Real API integration (`/api/v1/clients`, `/api/v1/clients/groups`)
- ✅ Stats cards with proper branding colors
- ✅ System health percentage indicator
- ✅ Quick actions grid
- ✅ Recently active clients table
- ✅ Responsive design
- ✅ Loading states
- ✅ Empty states
- ✅ Error handling

## Remaining Work ⏳

### Critical Pages to Create

1. **Client Management (`/web/src/routes/clients/+page.svelte`)** - HIGH PRIORITY
   - Full client list with filtering
   - Filter by: status (online/offline), OS type, tags, groups
   - Search by hostname, IP, MAC address
   - Bulk actions (add to group, run query, delete)
   - Columns: Hostname, OS, IP, MAC, Status, Last Seen, Actions
   - Pagination
   - Real-time status updates

2. **Client Details (`/web/src/routes/clients/[id]/+page.svelte`)** - HIGH PRIORITY
   - Client overview (hostname, OS, hardware specs)
   - Real-time status
   - Recent check-ins history
   - Tags management
   - Group memberships
   - Hardware & software inventory
   - Configuration management
   - OSQuery results
   - Actions: Delete, Run Query, Update Config

3. **Client Groups (`/web/src/routes/groups/+page.svelte`)** - HIGH PRIORITY
   - List all groups
   - Create new group
   - Edit group criteria
   - View group members
   - Bulk assign clients
   - Group-based queries
   - Group-based policies

4. **Client Enrollment (`/web/src/routes/enrollment/+page.svelte`)** - MEDIUM PRIORITY
   - Generate enrollment keys
   - Manual enrollment form
   - Agent download links (macOS, Linux, Windows)
   - Enrollment instructions
   - Recent enrollments list

5. **OSQuery Management (`/web/src/routes/osquery/+page.svelte`)** - HIGH PRIORITY
   - Execute ad-hoc queries
   - Select target clients/groups
   - View query results in real-time
   - Export results
   - Save queries
   - Query history

6. **Query Library (`/web/src/routes/queries/+page.svelte`)** - MEDIUM PRIORITY
   - Saved queries list
   - Query packs
   - Create/edit queries
   - Schedule queries
   - Query templates
   - Search queries

7. **User Management (`/web/src/routes/users/+page.svelte`)** - MEDIUM PRIORITY
   - User list
   - Create/edit users
   - Assign roles (admin, operator, viewer, user)
   - Manage permissions
   - User activity

8. **Audit Logs (`/web/src/routes/audit/+page.svelte`)** - MEDIUM PRIORITY
   - Searchable audit log
   - Filter by: user, action, resource type, date range
   - Export logs
   - Real-time updates

9. **Error Pages**
   - `/web/src/routes/+error.svelte` - Use ERROR-generic.png
   - Custom 404 page - Use ERROR-404.png

### UI Components to Create (`/web/src/lib/components/`)

1. **ClientCard.svelte** - Reusable client display card
2. **StatusBadge.svelte** - Status indicator (online/offline/pending)
3. **FilterBar.svelte** - Filter controls for tables
4. **DataTable.svelte** - Reusable table with sorting/filtering
5. **Modal.svelte** - Modal dialog component
6. **Toast.svelte** - Notification toasts
7. **LoadingSpinner.svelte** - Loading indicator
8. **EmptyState.svelte** - Empty state placeholder

### API Integration (`/web/src/lib/api.ts`)

✅ Already exists, but needs updates:

- ⏳ Add all client endpoints
- ⏳ Add OSQuery endpoints
- ⏳ Add user management endpoints
- ⏳ Add audit log endpoints
- ⏳ Add WebSocket support for real-time updates
- ⏳ Add error handling middleware
- ⏳ Add authentication token management

### Theme & Styling

✅ Fixed major issues:

- ⏳ Update tailwind.config to use theme colors as CSS variables
- ⏳ Create reusable button styles
- ⏳ Create reusable form styles
- ⏳ Add dark mode toggle (optional)
- ⏳ Add responsive breakpoints

## Color Usage Guide

Based on `pkg/branding/theme.json`:

```css
/* Backgrounds */
--bg-primary: #1c2f38;      /* Main background */
--bg-secondary: #31413e;    /* Cards, panels */

/* Accents */
--accent-gold: #d4af37;     /* Primary actions, highlights */

/* Status Colors */
--success: #4ade80;         /* Online, healthy, success */
--error: #ef4444;           /* Offline, errors, alerts */
--warning: #fbbf24;         /* Warnings, pending */
--info: #60a5fa;            /* Info messages */

/* Text Colors */
--text-primary: #ffffff;    /* Main text */
--text-secondary: #94a3b8;  /* Secondary text */
--text-tertiary: #64748b;   /* Muted text */
--text-heading: #d4af37;    /* Section headings */

/* Borders */
--border-default: #334155;  /* Default borders */
--border-light: #475569;    /* Subtle borders */
```

## Implementation Priority

### Phase 1: Core MDM Functionality (THIS WEEK)

1. ✅ Layout redesign
2. ✅ Dashboard page
3. ⏳ Clients list page
4. ⏳ Client details page
5. ⏳ Client groups page
6. ⏳ OSQuery execution page

### Phase 2: Management Features (NEXT WEEK)

1. ⏳ Enrollment page
2. ⏳ Query library page
3. ⏳ User management page
4. ⏳ Audit logs page

### Phase 3: Polish & Enhancement

1. ⏳ Error pages with branded assets
2. ⏳ Real-time WebSocket updates
3. ⏳ Advanced filtering
4. ⏳ Bulk operations
5. ⏳ Export functionality
6. ⏳ Search improvements

## Design Principles

1. **MDM-First**: Clients and device management are the PRIMARY focus
2. **Clean UI**: No emojis, proper icons only
3. **Consistent Branding**: Always use theme colors
4. **Responsive**: Mobile, tablet, desktop
5. **Accessible**: Proper ARIA labels, keyboard navigation
6. **Real-time**: Live status updates where applicable
7. **Performant**: Lazy loading, pagination, efficient rendering

## Testing Checklist

- [ ] All pages load without errors
- [ ] Navigation works correctly
- [ ] Filtering works on all list pages
- [ ] Search functionality works
- [ ] Real-time updates work
- [ ] Responsive design on mobile/tablet
- [ ] Error states display correctly
- [ ] Loading states display correctly
- [ ] Empty states display correctly
- [ ] All API integrations work
- [ ] Colors match branding guide
- [ ] Fonts are properly loaded
- [ ] Assets are properly referenced
- [ ] No console errors

## Assets Integration Checklist

- ✅ Mobius_Logo.png - Used in sidebar
- ✅ Mobius-Logo-Text_1.png - Used in dashboard header
- [ ] ERROR-404.png - Create 404 page
- [ ] ERROR-generic.png - Create error page
- [ ] favicon.svg - Add to app.html
- [ ] favicon.ico - Add fallback favicon
- [ ] mobius_wallpaper.png - Optional: Login page background

## Notes

- The old purple-blue gradient aesthetic has been completely removed
- All components now use the gold accent (#d4af37) for highlights
- Infrastructure features (K8s, Postgres, VPN) are de-emphasized in navigation
- Focus is on client device management, grouping, and monitoring
- Real-time status indicators use proper status colors (green=online, gray=offline)
