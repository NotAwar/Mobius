# API Rate Limiting

Mobius API implements rate limiting to protect against excessive API usage and ensure fair resource allocation.

## Configuration

Rate limiting is configured in the API server configuration:

```go
Config{
    EnableRateLimiter: true,
    RateLimitMax:      100,                // Maximum requests
    RateLimitWindow:   1 * time.Minute,    // Time window
}
```

## Default Limits

- **Default Rate**: 100 requests per minute per IP address
- **Status Code**: 429 (Too Many Requests) when limit is exceeded

## Rate Limit Response

When the rate limit is exceeded, the API returns:

```json
{
  "error": "Too many requests",
  "message": "Rate limit exceeded. Maximum 100 requests per 1m0s allowed.",
  "request_id": "abc123",
  "timestamp": "2025-12-17T22:30:00Z",
  "retry_after": 60
}
```

## Headers

The following headers are included in responses:

- `X-RateLimit-Limit`: Maximum number of requests allowed in the time window
- `X-RateLimit-Remaining`: Number of requests remaining in the current window
- `X-RateLimit-Reset`: Unix timestamp when the rate limit resets

## Rate Limiting Strategy

- **Key Generation**: Rate limits are applied per IP address
- **Storage**: In-memory storage (suitable for single-instance deployments)
- **Algorithm**: Sliding window counter

## Customization

To customize rate limits, modify the `Config` in your server initialization:

```go
config := api.Config{
    Port:              "3001",
    Kubeconfig:        "configs/cluster/kubeconfig",
    EnableRateLimiter: true,
    RateLimitMax:      200,             // Increase to 200 requests
    RateLimitWindow:   2 * time.Minute, // per 2 minutes
}
```

## Disabling Rate Limiting

To disable rate limiting (not recommended for production):

```go
config := api.Config{
    EnableRateLimiter: false,
}
```

## Production Considerations

For production deployments with multiple API instances:

1. **Distributed Storage**: Replace in-memory storage with Redis or similar:

   ```go
   Storage: redis_storage.New(redis_storage.Config{
       Host: "localhost",
       Port: 6379,
   })
   ```

2. **Adjust Limits**: Set appropriate limits based on your use case:
   - Public API: 60-100 requests/minute
   - Internal API: 500-1000 requests/minute
   - Admin API: Higher or no limits

3. **Per-User Limits**: Implement authentication-based rate limiting:

   ```go
   KeyGenerator: func(c *fiber.Ctx) string {
       // Rate limit by authenticated user
       userID := c.Locals("user_id")
       if userID != nil {
           return fmt.Sprintf("user:%v", userID)
       }
       return c.IP()
   }
   ```

## Monitoring

Rate limit events are logged:

```
[WARN] Rate limit exceeded for IP: 192.168.1.100
```

Monitor these logs to:

- Identify potential abuse
- Adjust rate limits appropriately
- Detect legitimate high-traffic users who may need higher limits

## Best Practices

1. **Communicate Limits**: Document rate limits in your API documentation
2. **Progressive Backoff**: Implement exponential backoff in clients
3. **Whitelist Critical IPs**: Exempt monitoring systems or critical integrations
4. **Alert on Abuse**: Set up alerts for repeated rate limit violations
5. **Graceful Degradation**: Design clients to handle 429 responses gracefully
