package middleware

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// RateLimiter middleware для ограничения количества запросов
func RateLimiter(requests int, per time.Duration) gin.HandlerFunc {
	limiter := rate.NewLimiter(rate.Every(per/time.Duration(requests)), requests)
	return func(c *gin.Context) {
		if !limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "too many requests",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}
