package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// BindJSON middleware для валидации JSON-запросов и сохранения результата в контексте
func BindJSON[T any]() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req T
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid input"})
			c.Abort()
			return
		}
		c.Set("request", req)
		c.Next()
	}
}

// GetRequest извлекает валидированный запрос из контекста
func GetRequest[T any](c *gin.Context) (T, bool) {
	req, exists := c.Get("request")
	if !exists {
		var zero T
		return zero, false
	}
	if r, ok := req.(T); ok {
		return r, true
	}
	var zero T
	return zero, false
}
