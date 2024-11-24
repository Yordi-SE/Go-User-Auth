package infrastructure

import (
	"fmt"
	"net/http"
	"strings"
	errors "user_authorization/error"
	"user_authorization/usecases/interfaces"

	"github.com/gin-gonic/gin"
)

// CORSMiddleware struct
type CORSMiddleware struct {
}

// NewCORSMiddleware creates a new CORSMiddleware
func NewCORSMiddleware() *CORSMiddleware {
	return &CORSMiddleware{}
}



// CORSMiddleware middleware
func (cors *CORSMiddleware) CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusOK)
			return
		}
		c.Next()
	}
}


// AuthMiddleware middleware
func AuthMiddleware(jwtService interfaces.JWTServiceI) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer c.Next()
		authHeader := c.GetHeader("Authorization")
		fmt.Println(authHeader)
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": errors.NewCustomError("Authorization header is required", http.StatusUnauthorized),
			})
			c.Abort()
		
			return
		}
		authPart := strings.Split(authHeader, " ")
		if len(authPart) != 2 || strings.ToLower(authPart[0]) != "bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": errors.NewCustomError("Invalid token", http.StatusUnauthorized),
			})
			c.Abort()
			return
		}

		token, err := jwtService.ValidateAccessToken(authPart[1])
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": err,
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
		user_id := c.Param("user_id")
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
		if !exists || ((id == "" || id == nil || id != user_id) && role != "admin") {
			c.JSON(http.StatusForbidden, gin.H{
				"error": errors.NewCustomError("Unauthorized", http.StatusForbidden),
			})
			c.Abort()
			return
		}

		
	}
}