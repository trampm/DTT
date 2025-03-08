package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestSecurityHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		expectedHeader map[string]string
	}{
		{
			name: "Проверка security заголовков",
			expectedHeader: map[string]string{
				"X-XSS-Protection":        "1; mode=block",
				"X-Frame-Options":         "DENY",
				"X-Content-Type-Options":  "nosniff",
				"Content-Security-Policy": "default-src 'self'; img-src 'self' https: data:; font-src 'self' https:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';",
				"Cache-Control":           "no-store",
				"Pragma":                  "no-cache",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			_, r := gin.CreateTestContext(w)

			r.Use(SecurityHeaders())
			r.GET("/test", func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			req := httptest.NewRequest("GET", "/test", nil)
			r.ServeHTTP(w, req)

			for key, value := range tt.expectedHeader {
				assert.Equal(t, value, w.Header().Get(key))
			}
		})
	}
}

func TestRateLimiter(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name          string
		requests      int
		duration      time.Duration
		numRequests   int
		expectedCodes []int
	}{
		{
			name:          "В пределах лимита",
			requests:      2,
			duration:      time.Second,
			numRequests:   2,
			expectedCodes: []int{http.StatusOK, http.StatusOK},
		},
		{
			name:          "Превышение лимита",
			requests:      1,
			duration:      time.Second,
			numRequests:   2,
			expectedCodes: []int{http.StatusOK, http.StatusTooManyRequests},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			_, r := gin.CreateTestContext(w)

			r.Use(RateLimiter(tt.requests, tt.duration))
			r.GET("/test", func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			for i := 0; i < tt.numRequests; i++ {
				w = httptest.NewRecorder()
				req := httptest.NewRequest("GET", "/test", nil)
				req.RemoteAddr = "127.0.0.1:12345" // Устанавливаем IP для rate limiter
				r.ServeHTTP(w, req)
				assert.Equal(t, tt.expectedCodes[i], w.Code)
			}
		})
	}
}
