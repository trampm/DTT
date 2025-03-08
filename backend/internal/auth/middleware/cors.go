package middleware

import (
	"backend/internal/config"

	"github.com/gin-gonic/gin"
)

// CORS middleware для обработки Cross-Origin Resource Sharing
func CORS(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// Проверяем, разрешен ли данный origin
		allowedOrigin := "*"
		for _, allowed := range cfg.CORS.AllowOrigins {
			if allowed == origin {
				allowedOrigin = origin
				break
			}
		}

		c.Writer.Header().Set("Access-Control-Allow-Origin", allowedOrigin)

		if cfg.CORS.AllowCredentials {
			c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")
		c.Writer.Header().Set("Access-Control-Max-Age", cfg.CORS.MaxAge.String())

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}
