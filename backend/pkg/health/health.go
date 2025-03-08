package health

import (
	"net/http"
	"runtime"
	"time"

	"backend/pkg/logger"
	"backend/pkg/metrics"

	"github.com/gin-gonic/gin"
)

// PingableDB интерфейс для проверки соединения с базой данных
type PingableDB interface {
	Ping() error
}

// HealthChecker структура для проверки здоровья системы
type HealthChecker struct {
	db PingableDB
}

type HealthStatus struct {
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
}

type DetailedHealth struct {
	Status    string `json:"status"`
	Database  string `json:"database"`
	Timestamp string `json:"timestamp"`
}

// NewHealthChecker создает новый экземпляр HealthChecker
func NewHealthChecker(db PingableDB) *HealthChecker {
	return &HealthChecker{
		db: db,
	}
}

// CheckHealth проверяет здоровье системы
func (h *HealthChecker) CheckHealth(c *gin.Context) {
	ctx := c.Request.Context()
	traceID := logger.GetTraceID(ctx)
	start := time.Now()

	status := "UP"
	dbStatus := "UP"
	dbDetails := "Database connection is healthy"

	if err := h.db.Ping(); err != nil {
		status = "DOWN"
		dbStatus = "DOWN"
		dbDetails = "Database connection failed"
		logger.Logger.Error(ctx, "Database ping failed", err)
	} else {
		logger.Logger.Info(ctx, "Health check completed successfully")
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	duration := time.Since(start).Seconds()
	metrics.HealthCheckDuration.WithLabelValues("full", status).Observe(duration)

	c.JSON(http.StatusOK, gin.H{
		"status":   status,
		"trace_id": traceID,
		"components": gin.H{
			"database": gin.H{
				"status":  dbStatus,
				"details": dbDetails,
			},
			"memory": gin.H{
				"allocated": m.Alloc,
				"total":     m.TotalAlloc,
				"system":    m.Sys,
			},
		},
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// LivenessProbe проверяет, жив ли сервис
func (h *HealthChecker) LivenessProbe(c *gin.Context) {
	ctx := c.Request.Context()
	traceID := logger.GetTraceID(ctx)
	start := time.Now()

	logger.Logger.Info(ctx, "Liveness probe checked")

	duration := time.Since(start).Seconds()
	metrics.HealthCheckDuration.WithLabelValues("liveness", "UP").Observe(duration)

	c.JSON(http.StatusOK, gin.H{
		"status":   "UP",
		"trace_id": traceID,
	})
}

// ReadinessProbe проверяет, готов ли сервис обрабатывать запросы
func (h *HealthChecker) ReadinessProbe(c *gin.Context) {
	ctx := c.Request.Context()
	traceID := logger.GetTraceID(ctx)
	start := time.Now()

	if err := h.db.Ping(); err != nil {
		logger.Logger.Error(ctx, "Readiness probe failed: database unavailable", err)
		duration := time.Since(start).Seconds()
		metrics.HealthCheckDuration.WithLabelValues("readiness", "DOWN").Observe(duration)
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status":   "DOWN",
			"reason":   "Database connection failed",
			"trace_id": traceID,
		})
		return
	}

	logger.Logger.Info(ctx, "Readiness probe succeeded")
	duration := time.Since(start).Seconds()
	metrics.HealthCheckDuration.WithLabelValues("readiness", "UP").Observe(duration)

	c.JSON(http.StatusOK, gin.H{
		"status":   "UP",
		"trace_id": traceID,
	})
}
