# API Structure and Routes

## Base URL

```
http://localhost:3001/api/v1
```

## Authentication

All endpoints (except health checks) will require authentication once implemented.

## Response Format

All responses follow this structure:

```json
{
  "data": {},
  "error": null,
  "request_id": "uuid",
  "timestamp": "2025-12-17T22:00:00Z"
}
```

Error responses:

```json
{
  "error": "Error message",
  "request_id": "uuid",
  "timestamp": "2025-12-17T22:00:00Z"
}
```

---

## Health & Monitoring

### Health Checks

- `GET /health` - Basic health check
- `GET /health/detailed` - Detailed service health
- `GET /health/live` - Kubernetes liveness probe
- `GET /health/ready` - Kubernetes readiness probe

### Status

- `GET /status/cluster` - Cluster status summary
- `GET /status/postgres` - PostgreSQL status
- `GET /status/headscale` - Headscale VPN status

---

## Cluster Management

### Nodes

- `GET /cluster/nodes` - List all Kubernetes nodes
- `GET /cluster/nodes/:name` - Get specific node details
- `GET /cluster/nodes/:name/metrics` - Get node resource metrics

### Pods

- `GET /cluster/pods` - List all pods (all namespaces)
- `GET /cluster/pods?namespace=:namespace` - List pods in namespace
- `GET /cluster/pods/:namespace/:name` - Get specific pod
- `GET /cluster/pods/:namespace/:name/logs` - Get pod logs
- `DELETE /cluster/pods/:namespace/:name` - Delete pod

### Namespaces

- `GET /cluster/namespaces` - List all namespaces
- `GET /cluster/namespaces/:name` - Get namespace details
- `POST /cluster/namespaces` - Create namespace
- `DELETE /cluster/namespaces/:name` - Delete namespace

### Deployments

- `GET /cluster/deployments` - List all deployments
- `GET /cluster/deployments/:namespace/:name` - Get deployment
- `POST /cluster/deployments` - Create deployment
- `PUT /cluster/deployments/:namespace/:name` - Update deployment
- `DELETE /cluster/deployments/:namespace/:name` - Delete deployment
- `POST /cluster/deployments/:namespace/:name/scale` - Scale deployment

---

## PostgreSQL Management (CNPG)

### Database Clusters

- `GET /postgres/clusters` - List all CNPG clusters
- `GET /postgres/clusters/:namespace/:name` - Get cluster details
- `POST /postgres/clusters` - Create new cluster
- `DELETE /postgres/clusters/:namespace/:name` - Delete cluster

### Databases (DEPRECATED - Use clusters)

- `GET /postgres/databases` - List databases (legacy)
- `POST /postgres/databases` - Create database cluster
- `DELETE /postgres/databases/:name` - Delete database cluster

### Backups

- `GET /postgres/backups/:namespace/:cluster` - List backups for cluster
- `POST /postgres/backups/:namespace/:cluster` - Create backup
- `POST /postgres/restore/:namespace/:cluster` - Restore from backup

---

## Headscale VPN Management

### Users

- `GET /headscale/users` - List all Headscale users
- `GET /headscale/users/:name` - Get user details
- `POST /headscale/users` - Create new user
- `DELETE /headscale/users/:name` - Delete user

### Nodes (Machines)

- `GET /headscale/nodes` - List all VPN nodes
- `GET /headscale/nodes/:id` - Get node details
- `POST /headscale/nodes/:id/routes` - Enable routes for node
- `DELETE /headscale/nodes/:id` - Delete/deregister node

### Preauthentication Keys

- `GET /headscale/preauthkeys/:user` - List preauth keys for user
- `POST /headscale/preauthkeys/:user` - Create preauth key
- `DELETE /headscale/preauthkeys/:key` - Expire/delete key

---

## Client Management

### Clients

- `GET /clients` - List all managed clients
- `GET /clients/:id` - Get client details
- `POST /clients` - Register new client (onboarding)
- `PUT /clients/:id` - Update client information
- `DELETE /clients/:id` - Remove client

### Client Configuration

- `GET /clients/:id/config` - Get client configuration
- `PUT /clients/:id/config` - Update client configuration
- `POST /clients/:id/config/push` - Push config to client

### Client Groups

- `GET /clients/groups` - List all client groups
- `GET /clients/groups/:id` - Get group details
- `POST /clients/groups` - Create client group
- `PUT /clients/groups/:id` - Update group
- `DELETE /clients/groups/:id` - Delete group
- `POST /clients/groups/:id/members` - Add clients to group
- `DELETE /clients/groups/:id/members/:clientId` - Remove from group

### Client Actions

- `POST /clients/:id/ssh` - Execute SSH command
- `POST /clients/:id/restart` - Restart client agent
- `GET /clients/:id/status` - Get real-time client status

---

## OSQuery Data Ingestion

### Results

- `POST /osquery/results` - Ingest OSQuery results (bulk)
- `GET /osquery/results/:clientId` - Get results for client
- `GET /osquery/results/:clientId/:query` - Get specific query results

### Queries

- `GET /osquery/queries` - List all scheduled queries
- `GET /osquery/queries/:name` - Get query details
- `POST /osquery/queries` - Create new query
- `PUT /osquery/queries/:name` - Update query
- `DELETE /osquery/queries/:name` - Delete query

### Packs

- `GET /osquery/packs` - List all query packs
- `GET /osquery/packs/:name` - Get pack details
- `POST /osquery/packs` - Create new pack
- `PUT /osquery/packs/:name` - Update pack
- `DELETE /osquery/packs/:name` - Delete pack

### Configuration

- `GET /osquery/config/:clientId` - Get OSQuery config for client
- `POST /osquery/config/global` - Update global OSQuery config

---

## Audit Logging

### Logs

- `GET /audit/logs` - List audit logs (paginated)
- `GET /audit/logs/:id` - Get specific audit log
- `GET /audit/logs/user/:userId` - Get logs for user
- `GET /audit/logs/resource/:type/:id` - Get logs for resource

### Export

- `POST /audit/export` - Export audit logs (CSV/JSON)

---

## Future Endpoints (Planned)

### Metrics

- `GET /metrics` - Prometheus metrics endpoint
- `GET /metrics/cluster` - Cluster-specific metrics
- `GET /metrics/clients` - Client metrics summary

### Webhooks

- `GET /webhooks` - List configured webhooks
- `POST /webhooks` - Create webhook
- `DELETE /webhooks/:id` - Delete webhook
- `POST /webhooks/:id/test` - Test webhook

### Notifications

- `GET /notifications` - List notifications
- `POST /notifications/send` - Send notification
- `PUT /notifications/:id/read` - Mark as read

---

## Rate Limiting

All endpoints are rate-limited to:

- **Default**: 100 requests per minute per IP
- **Authenticated**: 500 requests per minute per user

Rate limit headers:

- `X-RateLimit-Limit`
- `X-RateLimit-Remaining`
- `X-RateLimit-Reset`

---

## Error Codes

- `200` - Success
- `201` - Created
- `204` - No Content
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `409` - Conflict
- `429` - Too Many Requests
- `500` - Internal Server Error
- `503` - Service Unavailable
