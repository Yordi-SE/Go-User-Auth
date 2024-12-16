package infrastructure

import (
	"net/http"
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

//secure  headers middleware
func SecureHeadersMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
        c.Writer.Header().Set("X-Frame-Options", "DENY")
        c.Writer.Header().Set("X-XSS-Protection", "1; mode=block")
        c.Writer.Header().Set("Content-Security-Policy", "default-src 'self'")
        c.Next()
    }
}

var limiter = rate.NewLimiter(1, 5)

// Middleware to check the rate limit.
func RateLimitMiddleware()  gin.HandlerFunc {
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
			c.JSON(http.StatusUnauthorized,gin.H{
				"error": errors.NewCustomError("Invalid token", http.StatusUnauthorized),
			})
			c.Abort()
			return
		}
		refresh_token, err := c.Cookie("refresh_token")
		if err != nil {
			c.JSON(http.StatusUnauthorized,gin.H{
				"error": errors.NewCustomError("Invalid token", http.StatusUnauthorized),
			})
			c.Abort()
			return
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
		if role == nil || id == nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": errors.NewCustomError("Invalid token claims", http.StatusUnauthorized),
			})
			c.Abort()
			return
		}
		c.Set("role",role)
		c.Set("user_id",id)
		c.Set("Authorization",access_token)
		c.Set("Refresh", refresh_token)
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
		if !exists  {
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