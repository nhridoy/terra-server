package auth

import (
	"crypto/subtle"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type RateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	limit    int
	window   time.Duration
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		attempts: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
	// Background cleanup every 5 minutes to prevent memory leak
	go rl.cleanup()
	return rl
}

func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-rl.window)

	attempts := rl.attempts[key]
	valid := make([]time.Time, 0)
	for _, t := range attempts {
		if t.After(windowStart) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= rl.limit {
		rl.attempts[key] = valid
		return false
	}

	rl.attempts[key] = append(valid, now)
	return true
}

// cleanup removes expired entries periodically to prevent memory leak.
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		windowStart := now.Add(-rl.window)
		for key, attempts := range rl.attempts {
			valid := make([]time.Time, 0)
			for _, t := range attempts {
				if t.After(windowStart) {
					valid = append(valid, t)
				}
			}
			if len(valid) == 0 {
				delete(rl.attempts, key)
			} else {
				rl.attempts[key] = valid
			}
		}
		rl.mu.Unlock()
	}
}

// parseIP parses an IP address string, returning nil if invalid.
func parseIP(s string) net.IP {
	return net.ParseIP(strings.TrimSpace(s))
}

// isTrustedIP checks if an IP is in the trusted CIDR list.
func isTrustedIP(ip net.IP, trusted []*net.IPNet) bool {
	for _, cidr := range trusted {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// ParseCIDRs parses a list of CIDR strings into net.IPNet pointers.
func ParseCIDRs(cidrs []string) []*net.IPNet {
	var result []*net.IPNet
	for _, s := range cidrs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(s))
		if err == nil {
			result = append(result, network)
		}
	}
	return result
}

// TrustedClientIPMiddleware extracts the real client IP from X-Forwarded-For
// when the connection comes from a trusted proxy. Sets "clientIP" in gin.Context.
// Falls back to RemoteAddr when no trusted proxies are configured.
func TrustedClientIPMiddleware(trustedCIDRs []*net.IPNet) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(trustedCIDRs) > 0 {
			remoteIP := parseIP(c.Request.RemoteAddr)
			if remoteIP != nil && isTrustedIP(remoteIP, trustedCIDRs) {
				if xff := c.GetHeader("X-Forwarded-For"); xff != "" {
					// X-Forwarded-For: client, proxy1, proxy2
					// Take the first (leftmost) untrusted IP
					parts := strings.Split(xff, ",")
					for _, part := range parts {
						ip := parseIP(part)
						if ip != nil && !isTrustedIP(ip, trustedCIDRs) {
							c.Set("clientIP", ip.String())
							c.Next()
							return
						}
					}
				}
			}
		}
		// Default: use ClientIP (RemoteAddr when no proxies, or Gin's default)
		c.Set("clientIP", c.ClientIP())
		c.Next()
	}
}

func RateLimitMiddleware(limiter *RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := c.ClientIP()
		if !limiter.Allow(key) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "too many attempts, please try again later",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// RateLimitByKeyMiddleware is a rate limiter that uses a custom key function.
// This allows rate limiting by user ID, API key, etc. instead of just IP.
func RateLimitByKeyMiddleware(limiter *RateLimiter, keyFn func(*gin.Context) string) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := keyFn(c)
		if !limiter.Allow(key) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "too many attempts, please try again later",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// ConstantTimeErrorCompare performs a constant-time comparison of two error messages
// to prevent timing attacks on error responses.
func ConstantTimeErrorCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// GetClientIP returns the client IP from the gin context.
// Uses the value set by TrustedClientIPMiddleware if available.
func GetClientIP(c *gin.Context) string {
	if ip, ok := c.Get("clientIP"); ok {
		if s, ok := ip.(string); ok && s != "" {
			return s
		}
	}
	return c.ClientIP()
}
