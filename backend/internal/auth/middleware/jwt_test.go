package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"backend/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestJWTMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	secretKey := "secret"

	router := gin.Default()
	// Передаем utils.ValidateToken как второй аргумент
	router.Use(JWTMiddleware(secretKey, utils.ValidateToken))
	router.GET("/protected", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	t.Run("Успешная аутентификация", func(t *testing.T) {
		token, err := utils.GenerateToken(1, "user", []string{"read"}, secretKey)
		assert.NoError(t, err)

		req, _ := http.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Expected status 200 OK")
		assert.Contains(t, w.Body.String(), "success")
	})

	t.Run("Отсутствует заголовок Authorization", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/protected", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "Authorization header is required")
	})

	t.Run("Неверный формат токена", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", "InvalidToken")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid token format")
	})

	t.Run("Неверный токен", func(t *testing.T) {
		token, _ := utils.GenerateToken(1, "user", []string{"read"}, "wrongsecret")
		req, _ := http.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid token")
	})
}
