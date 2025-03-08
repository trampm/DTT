package middleware

import (
	"time"

	"backend/pkg/logger"

	"github.com/gin-gonic/gin"
)

// RequestLogger middleware для логирования HTTP запросов
func RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Время начала запроса
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Обработка запроса
		c.Next()

		// Время окончания запроса
		timestamp := time.Now()
		latency := timestamp.Sub(start)

		// Получение статуса ответа
		status := c.Writer.Status()

		if raw != "" {
			path = path + "?" + raw
		}

		// Логирование информации о запросе
		logger.Logger.Infof("[HTTP] %d | %13v | %15s | %s | %s",
			status,
			latency,
			c.ClientIP(),
			c.Request.Method,
			path,
		)
	}
}
