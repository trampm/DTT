package metrics

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// HTTPRequestsTotal считает общее количество HTTP запросов
	HTTPRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "endpoint", "status"},
	)

	// HTTPRequestDuration измеряет длительность HTTP запросов
	HTTPRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		},
		[]string{"method", "endpoint"},
	)

	// DatabaseQueriesTotal считает общее количество запросов к БД
	DatabaseQueriesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "database_queries_total",
			Help: "Total number of database queries",
		},
		[]string{"type", "status"},
	)

	// DatabaseErrors считает общее количество ошибок базы данных
	DatabaseErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "database_errors_total",
			Help: "Total number of database errors",
		},
		[]string{"type"},
	)

	// DatabaseSpecificErrors считает специфические ошибки базы данных (дедлоки, таймауты)
	DatabaseSpecificErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "database_specific_errors_total",
			Help: "Total number of specific database errors (e.g., deadlocks, timeouts)",
		},
		[]string{"error_type"},
	)

	// ActiveConnections показывает текущее количество активных соединений (HTTP)
	ActiveConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "active_connections",
			Help: "Number of currently active connections",
		},
	)

	// HealthCheckDuration измеряет длительность проверок здоровья
	HealthCheckDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "health_check_duration_seconds",
			Help:    "Duration of health checks in seconds",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1},
		},
		[]string{"type", "status"},
	)

	// DBOpenConnections показывает текущее количество открытых соединений с базой данных
	DBOpenConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "db_open_connections",
			Help: "Number of open database connections",
		},
	)

	// DBInUseConnections показывает текущее количество используемых соединений с базой данных
	DBInUseConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "db_in_use_connections",
			Help: "Number of in-use database connections",
		},
	)

	// DBIdleConnections показывает текущее количество простаивающих соединений с базой данных
	DBIdleConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "db_idle_connections",
			Help: "Number of idle database connections",
		},
	)

	// DBWaitCount показывает количество ожиданий соединений
	DBWaitCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "db_wait_count",
			Help: "Total number of times the pool had to wait for a new connection",
		},
	)

	// DBWaitDuration показывает общее время ожидания соединений
	DBWaitDuration = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "db_wait_duration_seconds",
			Help: "Total wait duration for new connections in seconds",
		},
	)

	// DBMaxOpenConnections показывает максимальное количество открытых соединений, заданное в конфигурации
	DBMaxOpenConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "db_max_open_connections",
			Help: "Maximum number of open database connections allowed",
		},
	)
)

func init() {
	// Регистрируем метрики в Prometheus
	prometheus.MustRegister(HTTPRequestsTotal)
	prometheus.MustRegister(HTTPRequestDuration)
	prometheus.MustRegister(DatabaseQueriesTotal)
	prometheus.MustRegister(DatabaseErrors)
	prometheus.MustRegister(DatabaseSpecificErrors)
	prometheus.MustRegister(ActiveConnections)
	prometheus.MustRegister(HealthCheckDuration)
	prometheus.MustRegister(DBOpenConnections)
	prometheus.MustRegister(DBInUseConnections)
	prometheus.MustRegister(DBIdleConnections)
	prometheus.MustRegister(DBWaitCount)
	prometheus.MustRegister(DBWaitDuration)
	prometheus.MustRegister(DBMaxOpenConnections)
}

// PrometheusMiddleware добавляет сбор метрик для HTTP запросов
func PrometheusMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path

		ActiveConnections.Inc()
		defer ActiveConnections.Dec()

		c.Next()

		status := c.Writer.Status()
		duration := time.Since(start).Seconds()

		HTTPRequestsTotal.WithLabelValues(
			c.Request.Method,
			path,
			strconv.Itoa(status),
		).Inc()

		HTTPRequestDuration.WithLabelValues(
			c.Request.Method,
			path,
		).Observe(duration)
	}
}

// PrometheusHandler возвращает handler для эндпоинта метрик
func PrometheusHandler() gin.HandlerFunc {
	h := promhttp.Handler()
	return func(c *gin.Context) {
		h.ServeHTTP(c.Writer, c.Request)
	}
}
