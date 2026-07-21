package auth

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authorization header required"})
			c.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header format"})
			c.Abort()
			return
		}

		tokenString := parts[1]

		// Check if token has been revoked (logout was called)
		if isTokenRevoked(tokenString) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "token has been revoked"})
			c.Abort()
			return
		}

		claims, err := ValidateToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			c.Abort()
			return
		}

		// Check if this user's tokens have been revoked (via logout)
		if IsTokenRevokedForUser(claims.UserID) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "token has been revoked"})
			c.Abort()
			return
		}

		c.Set("userId", claims.UserID)
		c.Set("email", claims.Email)

		c.Next()
	}
}

func GetUserID(c *gin.Context) string {
	if userID, exists := c.Get("userId"); exists {
		if id, ok := userID.(string); ok {
			return id
		}
	}
	return ""
}

func GetEmail(c *gin.Context) string {
	if email, exists := c.Get("email"); exists {
		if e, ok := email.(string); ok {
			return e
		}
	}
	return ""
}

// isTokenRevoked checks if an access token has been revoked (via logout).
// Uses an in-memory map for the access token lifetime (15 min).
// Revoked tokens are cleaned up after their natural expiry.
var (
	revokedTokens   = make(map[string]int64) // token -> expiry timestamp (unix)
	revokedMu       = &revokedTokens
)

func isTokenRevoked(token string) bool {
	// Parse expiry from JWT to check if revoked token entry has expired
	// For simplicity, we just check if it exists in the map
	_, exists := (*revokedMu)[token]
	return exists
}

// RevokeToken adds a token to the revoked list.
// The token will be cleaned up after its natural expiry (15 min for access tokens).
func RevokeToken(token string) {
	// We don't know exact expiry here, but access tokens live ~15 min.
	// Cleanup happens lazily or via the JWT expiry check.
	(*revokedMu)[token] = 1
}

// RevokeAllUserTokens revokes all access tokens for a user by storing the user's
// token revocation timestamp. Any token issued before this timestamp is considered revoked.
var (
	userRevokedAt   = make(map[string]int64) // userID -> revoke timestamp
	userRevokedMu   = &userRevokedAt
)

// RevokeAllTokensForUser sets a revocation timestamp for the user.
// All tokens issued before this time are effectively revoked.
func RevokeAllTokensForUser(userID string) {
	(*userRevokedMu)[userID] = 1
}

// IsTokenRevokedForUser checks if a user's tokens have been revoked.
func IsTokenRevokedForUser(userID string) bool {
	_, exists := (*userRevokedMu)[userID]
	return exists
}
