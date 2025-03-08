package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	authorizationHeader = "Authorization"
	userIDKey           = "userID"
	roleKey             = "role"
	permissionsKey      = "permissions"
)

// JWTMiddleware проверяет JWT токен и добавляет userID, role и permissions в контекст
func JWTMiddleware(secretKey string, validateToken func(string, string) (uint, string, []string, error)) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader(authorizationHeader)
		fmt.Printf("JWTMiddleware called. Authorization header: %s\n", header)
		if header == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			c.Abort()
			return
		}

		bearerToken := strings.Split(header, " ")
		if len(bearerToken) != 2 || bearerToken[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format"})
			c.Abort()
			return
		}

		userID, role, permissions, err := validateToken(bearerToken[1], secretKey)
		if err != nil || userID == 0 {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		c.Set(userIDKey, userID)
		c.Set(roleKey, role)
		c.Set(permissionsKey, permissions)
		c.Next()
	}
}

// GetUserID получает ID пользователя из контекста
func GetUserID(c *gin.Context) (uint, bool) {
	id, exists := c.Get(userIDKey)
	if !exists {
		return 0, false
	}

	switch v := id.(type) {
	case float64:
		return uint(v), true
	case uint:
		return v, true
	default:
		return 0, false
	}
}

// GetRole получает роль из контекста
func GetRole(c *gin.Context) (string, bool) {
	role, exists := c.Get(roleKey)
	if !exists {
		return "", false
	}
	if r, ok := role.(string); ok {
		return r, true
	}
	return "", false
}

// GetPermissions получает права из контекста
func GetPermissions(c *gin.Context) ([]string, bool) {
	perms, exists := c.Get(permissionsKey)
	if !exists {
		return nil, false
	}
	if p, ok := perms.([]string); ok {
		return p, true
	}
	return nil, false
}
