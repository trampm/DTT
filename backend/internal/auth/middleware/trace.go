package middleware

import (
	"backend/pkg/logger"
	"context"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// TraceMiddleware добавляет trace_id в контекст запроса
func TraceMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Проверяем, есть ли trace_id в заголовке X-Trace-ID (для совместимости с внешними системами)
		traceID := c.GetHeader("X-Trace-ID")
		if traceID == "" {
			// Если заголовок отсутствует, генерируем новый trace_id
			traceID = uuid.New().String()
		}

		// Добавляем trace_id в контекст для использования логгером
		ctx := context.WithValue(c.Request.Context(), logger.TraceIDKey, traceID)
		c.Request = c.Request.WithContext(ctx)

		// Добавляем trace_id в заголовок ответа для отладки
		c.Header("X-Trace-ID", traceID)

		// Переходим к следующему обработчику
		c.Next()
	}
}
