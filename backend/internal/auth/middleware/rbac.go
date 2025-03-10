package middleware

import (
	"net/http"

	"backend/internal/auth/service"

	"github.com/gin-gonic/gin"
)

func RBAC(authService service.AuthServiceInterface, requiredPermission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		permissions, exists := c.Get("permissions")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{"error": "Permissions not found"})
			c.Abort()
			return
		}

		perms, ok := permissions.(map[string]struct{})
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid permissions format"})
			c.Abort()
			return
		}

		if _, hasPerm := perms[requiredPermission]; !hasPerm {
			c.JSON(http.StatusForbidden, gin.H{"error": "Permission denied"})
			c.Abort()
			return
		}

		c.Next()
	}
}
