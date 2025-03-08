package middleware

import (
	"backend/pkg/logger"
	"context"

	"log/slog" // Import slog

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// TraceMiddleware добавляет trace_id и request_id в контекст запроса
func TraceMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		traceID := c.GetHeader("X-Trace-ID")
		if traceID == "" {
			traceID = uuid.New().String()
		}

		ctx := context.WithValue(c.Request.Context(), logger.TraceIDKey, traceID)
		requestID := uuid.New().String()
		ctx = context.WithValue(ctx, logger.RequestIDKey, requestID) // Добавляем request_id

		c.Request = c.Request.WithContext(ctx)
		c.Header("X-Trace-ID", traceID)
		c.Header("X-Request-ID", requestID) // Добавляем request_id в ответ

		// Log the start of the request
		logger.Logger.Info(ctx, "Request started", slog.String("method", c.Request.Method), slog.String("path", c.Request.URL.Path))

		c.Next()

		// Log the end of the request
		logger.Logger.Info(ctx, "Request completed", slog.Int("status", c.Writer.Status()))
	}
}
