package middleware

import (
	"sync"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// Структура для хранения лимитеров
type IPRateLimiter struct {
	ips   map[string]*rate.Limiter
	mu    *sync.RWMutex
	rate  rate.Limit
	burst int
}

// Создание нового rate limiter'а
func NewIPRateLimiter(r rate.Limit, b int) *IPRateLimiter {
	return &IPRateLimiter{
		ips:   make(map[string]*rate.Limiter),
		mu:    &sync.RWMutex{},
		rate:  r,
		burst: b,
	}
}

// Получение лимитера для IP
func (i *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
	i.mu.Lock()
	defer i.mu.Unlock()

	limiter, exists := i.ips[ip]
	if !exists {
		limiter = rate.NewLimiter(i.rate, i.burst)
		i.ips[ip] = limiter
	}

	return limiter
}

// SecurityHeaders добавляет заголовки безопасности
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Защита от XSS
		c.Header("X-XSS-Protection", "1; mode=block")
		// Защита от кликджекинга
		c.Header("X-Frame-Options", "DENY")
		// Защита от MIME-сниффинга
		c.Header("X-Content-Type-Options", "nosniff")
		// Политика безопасности контента
		c.Header("Content-Security-Policy", "default-src 'self'; img-src 'self' https: data:; font-src 'self' https:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';")
		// HSTS (только для production)
		if gin.Mode() == gin.ReleaseMode {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		// Отключение кеширования для API endpoints
		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")

		c.Next()
	}
}
