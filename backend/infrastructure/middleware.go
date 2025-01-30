package infrastructure

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	errors "user_authorization/error"
	"user_authorization/usecases/interfaces"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// CORSMiddleware struct
type CORSMiddleware struct {
}

// NewCORSMiddleware creates a new CORSMiddleware
func NewCORSMiddleware() *CORSMiddleware {
	return &CORSMiddleware{}
}

// secure  headers middleware
func SecureHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
		c.Writer.Header().Set("X-Frame-Options", "DENY")
		c.Writer.Header().Set("X-XSS-Protection", "1; mode=block")
		nonce := os.Getenv("NONCE") // Generate a random value for each request
		c.Writer.Header().Set("Content-Security-Policy", fmt.Sprintf("default-src 'self'; style-src 'self' 'nonce-%s'", nonce))
		c.Next()
	}
}

var limiter = rate.NewLimiter(1, 5)

// Middleware to check the rate limit.
func RateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "too many requests"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// AuthMiddleware middleware
func AuthMiddleware(jwtService interfaces.JWTServiceI) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer c.Next()
		access_token, err := c.Cookie("access_token")
		if err != nil {
			accessToken, errs := getTokenFromHeader(c)
			if errs != nil {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error": errors.NewCustomError("Invalid access token", http.StatusUnauthorized),
				})
				c.Abort()
				return
			}
			access_token = accessToken
		}
		token, errs := jwtService.ValidateAccessToken(access_token)
		if errs != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": errors.NewCustomError(errs.Error(), http.StatusUnauthorized),
			})
			c.Abort()
			return
		}

		if token == nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": errors.NewCustomError("Invalid token", http.StatusUnauthorized),
			})
			c.Abort()
			return
		}

		claims, ok := jwtService.FindClaim(token)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": errors.NewCustomError("Invalid token", http.StatusUnauthorized),
			})
			c.Abort()
			return
		}
		role := claims["role"]
		id := claims["user_id"]
		token_id := claims["token_id"]
		if role == nil || id == nil || token_id == nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": errors.NewCustomError("Invalid token claims", http.StatusUnauthorized),
			})
			c.Abort()
			return
		}
		c.Set("role", role)
		c.Set("user_id", id)
		c.Set("token_id", token_id)
		c.Set("Authorization", access_token)
	}
}

// AuthMiddleware middleware for admin
func AdminAuthMiddleware(jwtService interfaces.JWTServiceI) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer c.Next()
		role, exists := c.Get("role")
		if !exists || role != "admin" {
			c.JSON(http.StatusForbidden, gin.H{
				"error": errors.NewCustomError("Unauthorized", http.StatusForbidden),
			})
			c.Abort()
			return
		}
	}
}

// AuthMiddleware middleware for user to check user id for user specific routes
func UserAuthMiddleware(jwtService interfaces.JWTServiceI) gin.HandlerFunc {
	return func(c *gin.Context) {
		user_id := c.Param("id")
		defer c.Next()
		role, exists := c.Get("role")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{
				"error": errors.NewCustomError("Unauthorized", http.StatusForbidden),
			})
			c.Abort()
			return
		}
		if role == "admin" {
			return
		}
		id, exists := c.Get("user_id")

		if !exists || (id == "" || id == nil || id != user_id) {
			c.JSON(http.StatusForbidden, gin.H{
				"error": errors.NewCustomError("Unauthorized", http.StatusForbidden),
			})
			c.Abort()
			return
		}

	}
}

func getTokenFromHeader(c *gin.Context) (string, *errors.CustomError) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return "", errors.NewCustomError("authorization header missing", http.StatusBadRequest)
	}

	// format: "Bearer <token>"
	parts := strings.Split(authHeader, " ")
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return parts[1], nil
	}

	return "", errors.NewCustomError("invalid authorization header format", http.StatusBadRequest)
}
