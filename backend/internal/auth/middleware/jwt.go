package middleware

import (
	"backend/pkg/logger"
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
func JWTMiddleware(secretKey string, validateToken func(string, string) (uint, string, map[string]struct{}, error)) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		userID, role, permissions, err := validateToken(token, secretKey)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}
		if err != nil {
			logger.Logger.Errorf("Invalid JWT token: %v | IP: %s", err, c.ClientIP())
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}
		c.Set("user_id", userID)
		c.Set("role", role)
		c.Set("permissions", permissions)
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
func GetPermissions(c *gin.Context) (map[string]struct{}, bool) {
	perms, exists := c.Get(permissionsKey)
	if !exists {
		return nil, false
	}
	if p, ok := perms.(map[string]struct{}); ok {
		return p, true
	}
	return nil, false
}
