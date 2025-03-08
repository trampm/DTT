package middleware

import (
	"net/http"

	"backend/internal/auth/service"

	"github.com/gin-gonic/gin"
)

func RBAC(svc service.AuthServiceInterface, requiredPermission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Проверяем только наличие userID, не сохраняя его
		if _, exists := GetUserID(c); !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
			c.Abort()
			return
		}

		role, roleExists := GetRole(c)
		if !roleExists || role == "" {
			c.JSON(http.StatusForbidden, gin.H{"error": "user has no role"})
			c.Abort()
			return
		}

		permissions, permsExist := GetPermissions(c)
		if !permsExist {
			c.JSON(http.StatusForbidden, gin.H{"error": "no permissions found"})
			c.Abort()
			return
		}

		hasPermission := false
		for _, perm := range permissions {
			if perm == requiredPermission {
				hasPermission = true
				break
			}
		}

		if !hasPermission {
			c.JSON(http.StatusForbidden, gin.H{"error": "access denied"})
			c.Abort()
			return
		}

		c.Next()
	}
}
