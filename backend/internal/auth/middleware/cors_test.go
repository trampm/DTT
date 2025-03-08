package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"backend/internal/config"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestCORSMiddlewareBasic(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	cfg := &config.Config{
		CORS: config.CORSConfig{
			AllowOrigins:     []string{"http://localhost:3000"},
			AllowCredentials: true,
			MaxAge:           time.Hour,
		},
	}

	router.Use(CORS(cfg))
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	router.ServeHTTP(w, req)

	assert.Equal(t, "http://localhost:3000", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))
}

func TestCORSMiddlewareDetailed(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		method         string
		expectedCode   int
		expectedHeader map[string]string
	}{
		{
			name:         "Обычный запрос",
			method:       "GET",
			expectedCode: http.StatusOK,
			expectedHeader: map[string]string{
				"Access-Control-Allow-Origin":      "*",
				"Access-Control-Allow-Methods":     "POST, OPTIONS, GET, PUT, DELETE",
				"Access-Control-Allow-Headers":     "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With",
				"Access-Control-Allow-Credentials": "true",
			},
		},
		{
			name:         "Preflight запрос",
			method:       "OPTIONS",
			expectedCode: http.StatusNoContent,
			expectedHeader: map[string]string{
				"Access-Control-Allow-Origin":      "*",
				"Access-Control-Allow-Methods":     "POST, OPTIONS, GET, PUT, DELETE",
				"Access-Control-Allow-Headers":     "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With",
				"Access-Control-Allow-Credentials": "true",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			_, r := gin.CreateTestContext(w)

			// Добавляем CORS middleware
			r.Use(CORS(&config.Config{
				CORS: config.CORSConfig{
					AllowCredentials: true,
					MaxAge:           time.Hour * 24,
				},
			}))
			r.GET("/test", func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			req := httptest.NewRequest(tt.method, "/test", nil)
			r.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedCode, w.Code)

			// Проверяем заголовки CORS
			for key, value := range tt.expectedHeader {
				assert.Equal(t, value, w.Header().Get(key))
			}
		})
	}
}
