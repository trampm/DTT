package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestPrometheus(t *testing.T) {
	// Настраиваем тестовое окружение
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(PrometheusMiddleware())
	router.GET("/metrics", PrometheusHandler())
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	router.GET("/notfound", func(c *gin.Context) {
		c.Status(http.StatusNotFound)
	})
	router.POST("/create", func(c *gin.Context) {
		c.Status(http.StatusCreated)
	})

	t.Run("проверка сбора метрик для успешного GET-запроса", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		// Проверяем метрики
		w = httptest.NewRecorder()
		req = httptest.NewRequest("GET", "/metrics", nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
		body := w.Body.String()

		assert.Contains(t, body, `http_requests_total{method="GET",endpoint="/test",status="200"}`)
		assert.Contains(t, body, `http_request_duration_seconds_count{method="GET",endpoint="/test"}`)
		assert.Contains(t, body, "active_connections")
	})

	t.Run("проверка сбора метрик для ошибки 404", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/notfound", nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)

		// Проверяем метрики
		w = httptest.NewRecorder()
		req = httptest.NewRequest("GET", "/metrics", nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
		body := w.Body.String()

		assert.Contains(t, body, `http_requests_total{method="GET",endpoint="/notfound",status="404"}`)
		assert.Contains(t, body, `http_request_duration_seconds_count{method="GET",endpoint="/notfound"}`)
		assert.Contains(t, body, "active_connections")
	})

	t.Run("проверка сбора метрик для POST-запроса", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/create", nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusCreated, w.Code)

		// Проверяем метрики
		w = httptest.NewRecorder()
		req = httptest.NewRequest("GET", "/metrics", nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
		body := w.Body.String()

		assert.Contains(t, body, `http_requests_total{method="POST",endpoint="/create",status="201"}`)
		assert.Contains(t, body, `http_request_duration_seconds_count{method="POST",endpoint="/create"}`)
		assert.Contains(t, body, "active_connections")
	})
}
