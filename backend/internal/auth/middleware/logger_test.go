package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"backend/pkg/logger"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestRequestLogger(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name     string
		path     string
		method   string
		status   int
		expected []string
	}{
		{
			name:   "Успешный запрос",
			path:   "/test",
			method: "GET",
			status: http.StatusOK,
			expected: []string{
				"[HTTP]",
				"200",
				"GET",
				"/test",
			},
		},
		{
			name:   "Запрос с query параметрами",
			path:   "/test?param=value",
			method: "GET",
			status: http.StatusOK,
			expected: []string{
				"[HTTP]",
				"200",
				"GET",
				"/test?param=value",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Создаем буфер для логов
			var buf bytes.Buffer
			oldLogger := logger.Logger
			logger.Logger = logger.NewTestLogger(&buf)
			defer func() {
				logger.Logger = oldLogger
			}()

			w := httptest.NewRecorder()
			_, r := gin.CreateTestContext(w)

			r.Use(RequestLogger())
			r.GET("/test", func(c *gin.Context) {
				c.Status(tt.status)
			})

			req := httptest.NewRequest(tt.method, tt.path, nil)
			r.ServeHTTP(w, req)

			// Проверяем, что все ожидаемые строки есть в логе
			logOutput := buf.String()
			for _, expected := range tt.expected {
				assert.Contains(t, logOutput, expected, "Log should contain '%s'", expected)
			}
		})
	}
}
