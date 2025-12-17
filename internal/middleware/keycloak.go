package middleware

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
)

// KeycloakConfig holds Keycloak configuration
type KeycloakConfig struct {
	RealmURL     string // e.g., https://keycloak.example.com/auth/realms/mobius
	ClientID     string
	ClientSecret string
	Enabled      bool
}

// JWTClaims represents the JWT token claims
type JWTClaims struct {
	jwt.RegisteredClaims
	Email             string                 `json:"email"`
	EmailVerified     bool                   `json:"email_verified"`
	PreferredUsername string                 `json:"preferred_username"`
	GivenName         string                 `json:"given_name"`
	FamilyName        string                 `json:"family_name"`
	RealmAccess       map[string]interface{} `json:"realm_access"`
	ResourceAccess    map[string]interface{} `json:"resource_access"`
	Roles             []string               `json:"roles"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKSResponse represents the JWKS endpoint response
type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

// KeycloakAuth provides JWT authentication middleware
type KeycloakAuth struct {
	config     KeycloakConfig
	logger     *logrus.Logger
	publicKeys map[string]*rsa.PublicKey
	lastFetch  time.Time
}

// NewKeycloakAuth creates a new Keycloak authentication middleware
func NewKeycloakAuth(logger *logrus.Logger, config KeycloakConfig) *KeycloakAuth {
	ka := &KeycloakAuth{
		config:     config,
		logger:     logger,
		publicKeys: make(map[string]*rsa.PublicKey),
	}

	// Fetch public keys on initialization
	if config.Enabled {
		if err := ka.fetchPublicKeys(); err != nil {
			logger.Warnf("Failed to fetch Keycloak public keys: %v", err)
		}
	}

	return ka
}

// Middleware returns the authentication middleware function
func (ka *KeycloakAuth) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Skip if Keycloak is disabled (dev mode)
		if !ka.config.Enabled {
			ka.logger.Debug("Keycloak auth disabled, allowing request")
			return c.Next()
		}

		// Extract token from Authorization header
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":   "Missing authorization header",
				"message": "Please provide a valid JWT token in the Authorization header",
			})
		}

		// Parse "Bearer <token>"
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":   "Invalid authorization format",
				"message": "Authorization header must be 'Bearer <token>'",
			})
		}

		tokenString := parts[1]

		// Validate token
		claims, err := ka.validateToken(tokenString)
		if err != nil {
			ka.logger.Warnf("Token validation failed: %v", err)
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":   "Invalid token",
				"message": err.Error(),
			})
		}

		// Store user info in context
		c.Locals("user_id", claims.Subject)
		c.Locals("username", claims.PreferredUsername)
		c.Locals("email", claims.Email)
		c.Locals("roles", ka.extractRoles(claims))
		c.Locals("claims", claims)

		return c.Next()
	}
}

// RequireRole returns middleware that checks for specific roles
func (ka *KeycloakAuth) RequireRole(roles ...string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userRoles, ok := c.Locals("roles").([]string)
		if !ok {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error":   "Forbidden",
				"message": "No roles found in token",
			})
		}

		// Check if user has any of the required roles
		hasRole := false
		for _, requiredRole := range roles {
			for _, userRole := range userRoles {
				if userRole == requiredRole {
					hasRole = true
					break
				}
			}
			if hasRole {
				break
			}
		}

		if !hasRole {
			ka.logger.Warnf("User missing required role. Has: %v, Needs: %v", userRoles, roles)
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error":   "Forbidden",
				"message": fmt.Sprintf("Requires one of: %v", roles),
			})
		}

		return c.Next()
	}
}

// validateToken validates a JWT token
func (ka *KeycloakAuth) validateToken(tokenString string) (*JWTClaims, error) {
	// Refresh keys if needed (every 24 hours)
	if time.Since(ka.lastFetch) > 24*time.Hour {
		if err := ka.fetchPublicKeys(); err != nil {
			ka.logger.Warnf("Failed to refresh public keys: %v", err)
		}
	}

	// Parse token
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Get key ID from token header
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing kid in token header")
		}

		// Get public key for this kid
		publicKey, exists := ka.publicKeys[kid]
		if !exists {
			return nil, fmt.Errorf("public key not found for kid: %s", kid)
		}

		return publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is invalid")
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type")
	}

	return claims, nil
}

// fetchPublicKeys fetches public keys from Keycloak JWKS endpoint
func (ka *KeycloakAuth) fetchPublicKeys() error {
	jwksURL := fmt.Sprintf("%s/protocol/openid-connect/certs", ka.config.RealmURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", jwksURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	var jwks JWKSResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("failed to decode JWKS: %w", err)
	}

	// Convert JWKs to RSA public keys
	newKeys := make(map[string]*rsa.PublicKey)
	for _, jwk := range jwks.Keys {
		if jwk.Kty != "RSA" {
			continue
		}

		publicKey, err := ka.jwkToPublicKey(jwk)
		if err != nil {
			ka.logger.Warnf("Failed to convert JWK to public key: %v", err)
			continue
		}

		newKeys[jwk.Kid] = publicKey
	}

	ka.publicKeys = newKeys
	ka.lastFetch = time.Now()
	ka.logger.Infof("Fetched %d public keys from Keycloak", len(newKeys))

	return nil
}

// jwkToPublicKey converts a JWK to an RSA public key
func (ka *KeycloakAuth) jwkToPublicKey(jwk JWK) (*rsa.PublicKey, error) {
	// Decode modulus
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}

	// Decode exponent
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	// Convert bytes to big.Int
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}

// extractRoles extracts roles from JWT claims
func (ka *KeycloakAuth) extractRoles(claims *JWTClaims) []string {
	roles := make([]string, 0)

	// Extract realm roles
	if realmAccess, ok := claims.RealmAccess["roles"].([]interface{}); ok {
		for _, role := range realmAccess {
			if roleStr, ok := role.(string); ok {
				roles = append(roles, roleStr)
			}
		}
	}

	// Extract client roles for this client
	if resourceAccess, ok := claims.ResourceAccess[ka.config.ClientID].(map[string]interface{}); ok {
		if clientRoles, ok := resourceAccess["roles"].([]interface{}); ok {
			for _, role := range clientRoles {
				if roleStr, ok := role.(string); ok {
					roles = append(roles, fmt.Sprintf("client:%s", roleStr))
				}
			}
		}
	}

	// Also include roles from claims if present
	roles = append(roles, claims.Roles...)

	return roles
}

// GetUserID extracts user ID from fiber context
func GetUserID(c *fiber.Ctx) string {
	if userID, ok := c.Locals("user_id").(string); ok {
		return userID
	}
	return ""
}

// GetUsername extracts username from fiber context
func GetUsername(c *fiber.Ctx) string {
	if username, ok := c.Locals("username").(string); ok {
		return username
	}
	return ""
}

// GetRoles extracts roles from fiber context
func GetRoles(c *fiber.Ctx) []string {
	if roles, ok := c.Locals("roles").([]string); ok {
		return roles
	}
	return []string{}
}

// HasRole checks if user has a specific role
func HasRole(c *fiber.Ctx, role string) bool {
	roles := GetRoles(c)
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}
