# Mobius Web Dashboard

Modern web interface for managing Mobius infrastructure - Kubernetes clusters, PostgreSQL databases, and Headscale VPN.

## Architecture

- **Framework**: SvelteKit 2 with Svelte 5
- **Styling**: Tailwind CSS 4
- **Language**: TypeScript
- **API Client**: Custom fetch-based client with Svelte stores
- **Backend**: Fiber v2 REST API on port 3000

## Features

### Dashboard (`/`)

- Real-time monitoring of cluster, PostgreSQL, and Headscale status
- Health indicators with color-coded status badges
- Auto-refresh every 5 seconds
- Quick navigation to feature pages

### Cluster Management (`/cluster`)

- View Kubernetes nodes with status and roles
- Monitor pod status across namespaces
- Track restart counts
- Auto-refresh every 10 seconds

### PostgreSQL Management (`/postgres`)

- Create new databases
- View database list with size and status
- Delete databases with confirmation
- Auto-refresh every 10 seconds

### Headscale VPN Management (`/headscale`)

- Create VPN users
- View active users
- Monitor VPN nodes with online/offline status
- Track last seen timestamps
- Auto-refresh every 10 seconds

## Development

Start the development server:

```sh
npm run dev
```

The UI will be available at `http://localhost:5173` and connects to the Fiber API at `http://localhost:3000`.

## Building

Create a production build:

```sh
npm run build
```

Preview the production build:

```sh
npm run preview
```

## API Integration

The dashboard communicates with the Mobius Fiber API at `/api/v1`:

- `GET /api/v1/health` - API health check
- `GET /api/v1/status/cluster` - Cluster status
- `GET /api/v1/status/postgres` - PostgreSQL status
- `GET /api/v1/status/headscale` - Headscale status
- `GET /api/v1/cluster/nodes` - Kubernetes nodes
- `GET /api/v1/cluster/pods` - Kubernetes pods
- `GET /api/v1/postgres/databases` - List databases
- `POST /api/v1/postgres/databases` - Create database
- `DELETE /api/v1/postgres/databases/:name` - Delete database
- `GET /api/v1/headscale/users` - List VPN users
- `POST /api/v1/headscale/users` - Create VPN user
- `GET /api/v1/headscale/nodes` - List VPN nodes

## Project Structure

```
web/
├── src/
│   ├── lib/
│   │   └── api.ts              # API client and Svelte stores
│   ├── routes/
│   │   ├── +layout.svelte      # Root layout
│   │   ├── +page.svelte        # Dashboard homepage
│   │   ├── cluster/
│   │   │   └── +page.svelte    # Cluster management
│   │   ├── postgres/
│   │   │   └── +page.svelte    # Database management
│   │   └── headscale/
│   │       └── +page.svelte    # VPN management
│   └── app.html                # HTML template
├── static/                     # Static assets
├── package.json
├── svelte.config.js
├── tailwind.config.ts
├── tsconfig.json
└── vite.config.ts
```

## Tech Stack

- **SvelteKit 2**: Meta-framework for Svelte with routing and SSR
- **Svelte 5**: Modern reactive framework with runes syntax
- **Tailwind CSS 4**: Utility-first CSS framework
- **TypeScript**: Type-safe JavaScript
- **Vite**: Fast build tool and dev server

## Design System

- **Colors**: Dark mode optimized with blue, purple, and emerald accents
- **Components**: Card-based layouts with rounded corners and shadows
- **Typography**: Inter font family with antialiasing
- **Spacing**: Consistent padding and margin using Tailwind scale
- **Status Indicators**: Green (healthy), red (unhealthy), yellow (warning)

You can preview the production build with `npm run preview`.

> To deploy your app, you may need to install an [adapter](https://svelte.dev/docs/kit/adapters) for your target environment.
