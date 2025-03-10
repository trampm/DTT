package database

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"math/rand"
	"time"

	"backend/internal/config"
	"backend/pkg/health"
	"backend/pkg/logger"
	"backend/pkg/metrics"

	"github.com/lib/pq"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// GormDB интерфейс для работы с базой данных
type GormDB interface {
	AutoMigrate(dst ...interface{}) error
	Create(value interface{}) *gorm.DB
	First(dst interface{}, conds ...interface{}) *gorm.DB
	Exec(sql string, vars ...interface{}) *gorm.DB
	Save(value interface{}) *gorm.DB
	Preload(query string, args ...interface{}) *gorm.DB
	Find(dest interface{}, conds ...interface{}) *gorm.DB
	Delete(value interface{}, conds ...interface{}) *gorm.DB
	FirstOrCreate(dst interface{}, conds ...interface{}) *gorm.DB
	Model(value interface{}) *gorm.DB
	Where(query interface{}, args ...interface{}) *gorm.DB
	WithContext(ctx context.Context) *gorm.DB
	Begin(opts ...*sql.TxOptions) *gorm.DB
}

// DB структура для работы с базой данных
type DB struct {
	Client GormDB
	sqlDB  *sql.DB
	config *config.Config
	ctx    context.Context // Добавляем поле ctx
}

// Ensure DB implements health.PingableDB
var _ health.PingableDB = (*DB)(nil)

// logWithLevel логирует сообщение с заданным уровнем
func (db *DB) logWithLevel(level, msg string, args ...interface{}) {
	switch level {
	case "debug":
		logger.Logger.Debugf(msg, args...)
	case "info":
		logger.Logger.Infof(msg, args...)
	case "warn":
		logger.Logger.Warnf(msg, args...)
	case "error":
		logger.Logger.Errorf(msg, args...)
	default:
		logger.Logger.Infof(msg, args...)
	}
}

// retry выполняет операцию с повторными попытками и экспоненциальной задержкой
func (db *DB) retry(operation string, attempts int, delay time.Duration, fn func() error) error {
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if err := fn(); err != nil {
			lastErr = err
			if !isRetryableError(err) {
				return err
			}
			delay := calculateExponentialBackoff(attempt, delay)
			db.logWithLevel(db.config.Database.RetryAttemptLogLevel, "Operation %s failed (attempt %d/%d), retrying after %v: %v", operation, attempt, attempts, delay, err)
			select {
			case <-db.ctx.Done():
				return db.ctx.Err()
			case <-time.After(delay):
				continue
			}
		}
		return nil // Успешное выполнение
	}
	return fmt.Errorf("operation %s failed after %d attempts: %w", operation, attempts, lastErr)
}

// calculateExponentialBackoff вычисляет задержку с экспоненциальной прогрессией и jitter
func calculateExponentialBackoff(attempt int, baseDelay time.Duration) time.Duration {
	exponent := float64(attempt - 1)
	delay := float64(baseDelay) * math.Pow(2, exponent)
	jitter := float64(baseDelay) * rand.Float64() * 0.5
	return time.Duration(delay + jitter)
}

// isRetryableError проверяет, является ли ошибка временной
func isRetryableError(err error) bool {
	if pqErr, ok := err.(*pq.Error); ok {
		switch pqErr.Code {
		case "40001": // Serialization failure (deadlock)
			return true
		case "57014": // Query canceled (timeout)
			return true
		}
	}
	return false
}

// updatePoolMetrics обновляет метрики пула соединений
func (db *DB) updatePoolMetrics() {
	if db.sqlDB != nil {
		stats := db.sqlDB.Stats()
		metrics.DBOpenConnections.Set(float64(stats.OpenConnections))
		metrics.DBInUseConnections.Set(float64(stats.InUse))
		metrics.DBIdleConnections.Set(float64(stats.Idle))
		metrics.DBWaitCount.Add(float64(stats.WaitCount))
		metrics.DBWaitDuration.Set(stats.WaitDuration.Seconds())
		metrics.DBMaxOpenConnections.Set(float64(stats.MaxOpenConnections))
	}
}

// startMetricsUpdater запускает фоновый мониторинг состояния пула соединений
func (db *DB) startMetricsUpdater(interval time.Duration) {
	logger.Logger.Infof("Starting database pool monitoring with interval=%s", interval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-db.ctx.Done():
			logger.Logger.Info(context.Background(), "Database pool monitoring stopped")
			return
		case <-ticker.C:
			db.updatePoolMetrics()
			logger.Logger.Debugf("Updated database pool metrics: open=%d, idle=%d, max=%d",
				db.sqlDB.Stats().OpenConnections,
				db.sqlDB.Stats().Idle,
				db.sqlDB.Stats().MaxOpenConnections,
			)
		}
	}
}

// StartMonitoring запускает фоновый мониторинг состояния пула соединений
func (db *DB) StartMonitoring(ctx context.Context, interval time.Duration) {
	logger.Logger.Infof("Starting database pool monitoring with interval=%s", interval)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				logger.Logger.Info(context.Background(), "Database pool monitoring stopped")
				return
			case <-ticker.C:
				db.updatePoolMetrics()
				logger.Logger.Debugf("Updated database pool metrics: open=%d, idle=%d, max=%d",
					db.sqlDB.Stats().OpenConnections,
					db.sqlDB.Stats().Idle,
					db.sqlDB.Stats().MaxOpenConnections,
				)
			}
		}
	}()
}

// ConnectDB устанавливает соединение с базой данных
func ConnectDB(cfg *config.Config) (*DB, error) {
	dsn := cfg.GetDSN()
	logger.Logger.Infof("Connecting to database with DSN: %s", dsn)
	var db *gorm.DB
	err := (&DB{config: cfg}).retry("connect", cfg.Database.MaxRetries, cfg.Database.RetryDelay, func() error {
		start := time.Now()
		var connectErr error
		db, connectErr = gorm.Open(postgres.New(postgres.Config{
			DSN:                  dsn,
			PreferSimpleProtocol: true,
		}), &gorm.Config{
			DisableForeignKeyConstraintWhenMigrating: true,
		})
		duration := time.Since(start).Seconds()
		status := "success"
		if connectErr != nil {
			status = "error"
		}
		metrics.DatabaseQueriesTotal.WithLabelValues("connect", status).Inc()
		logger.Logger.Debugf("Database connection attempt took %f seconds", duration)
		return connectErr
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	// Apply the middleware
	gormQueryMiddleware(cfg)(db)
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get sql.DB: %w", err)
	}
	// Применение настроек пула соединений
	sqlDB.SetMaxOpenConns(cfg.Database.MaxOpenConns)
	sqlDB.SetMaxIdleConns(cfg.Database.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(cfg.Database.ConnMaxLifetime)
	sqlDB.SetConnMaxIdleTime(5 * time.Minute) // Устанавливаем максимальное время простаивания соединения

	ctx, _ := context.WithCancel(context.Background()) // Создаем контекст с отменой
	dbInstance := &DB{
		Client: db,
		sqlDB:  sqlDB,
		config: cfg,
		ctx:    ctx, // Инициализируем поле ctx
	}
	dbInstance.updatePoolMetrics()
	go dbInstance.startMetricsUpdater(1 * time.Minute) // Запускаем обновление метрик каждую минуту

	logger.Logger.Info(context.Background(), fmt.Sprintf(
		"Database connected with maxOpenConns=%d, maxIdleConns=%d, connMaxLifetime=%s, connTimeout=%s, maxRetries=%d, retryDelay=%s, monitoringInterval=%s",
		cfg.Database.MaxOpenConns, cfg.Database.MaxIdleConns, cfg.Database.ConnMaxLifetime, cfg.Database.ConnTimeout, cfg.Database.MaxRetries, cfg.Database.RetryDelay, cfg.Database.MonitoringInterval,
	))

	return dbInstance, nil // Возвращаем nil вместо cancel
}

// AutoMigrate выполняет миграцию для указанных моделей
func (db *DB) AutoMigrate(dst ...interface{}) error {
	return db.Client.AutoMigrate(dst...)
}

// Create создает новую запись в базе данных
func (db *DB) Create(value interface{}) *gorm.DB {
	return db.Client.Create(value)
}

// First находит первую запись, соответствующую условиям
func (db *DB) First(dst interface{}, conds ...interface{}) *gorm.DB {
	return db.Client.First(dst, conds...)
}

// Exec выполняет SQL-запрос
func (db *DB) Exec(sql string, vars ...interface{}) *gorm.DB {
	return db.Client.Exec(sql, vars...)
}

// Save сохраняет запись в базе данных
func (db *DB) Save(value interface{}) *gorm.DB {
	return db.Client.Save(value)
}

// Preload выполняет предварительную загрузку связанных данных
func (db *DB) Preload(query string, args ...interface{}) *gorm.DB {
	return db.Client.Preload(query, args...)
}

// Find находит записи, соответствующие условиям
func (db *DB) Find(dest interface{}, conds ...interface{}) *gorm.DB {
	return db.Client.Find(dest, conds...)
}

// Delete удаляет записи из базы данных
func (db *DB) Delete(value interface{}, conds ...interface{}) *gorm.DB {
	return db.Client.Delete(value, conds...)
}

// FirstOrCreate находит первую запись или создает новую, если она не существует
func (db *DB) FirstOrCreate(dst interface{}, conds ...interface{}) *gorm.DB {
	return db.Client.FirstOrCreate(dst, conds...)
}

// Model задает модель для запроса
func (db *DB) Model(value interface{}) *gorm.DB {
	return db.Client.Model(value)
}

// Where добавляет условие WHERE к запросу
func (db *DB) Where(query interface{}, args ...interface{}) *gorm.DB {
	return db.Client.Where(query, args...)
}

// BatchCreate выполняет пакетное создание записей в одной транзакции
func (db *DB) BatchCreate(ctx context.Context, values interface{}) error {
	return db.WithTransactionRetry(ctx, func(tx *gorm.DB) error {
		result := tx.Create(values)
		if result.Error != nil {
			return fmt.Errorf("batch create failed: %w", result.Error)
		}
		logger.Logger.Debugf("Batch created %d records", result.RowsAffected)
		return nil
	})
}

// WithTransactionRetry выполняет транзакцию с повторными попытками
func (db *DB) WithTransactionRetry(ctx context.Context, fn func(tx *gorm.DB) error) error {
	maxAttempts := db.config.Database.MaxRetries
	baseDelay := db.config.Database.RetryDelay
	if baseDelay == 0 {
		baseDelay = 100 * time.Millisecond // Значение по умолчанию
	}
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		tx := db.Client.WithContext(ctx).Begin()
		if tx.Error != nil {
			return fmt.Errorf("failed to begin transaction: %w", tx.Error)
		}
		defer func() {
			if r := recover(); r != nil {
				tx.Rollback()
				panic(r)
			}
		}()
		if err := fn(tx); err != nil {
			lastErr = err
			tx.Rollback()
			if !isRetryableError(err) {
				return err
			}
			delay := calculateExponentialBackoff(attempt, baseDelay)
			db.logWithLevel(db.config.Database.RetryAttemptLogLevel, "Operation %s failed (attempt %d/%d), retrying after %v: %v", "transaction", attempt, maxAttempts, delay, err)
			select {
			case <-db.ctx.Done(): // Используем поле ctx
				return db.ctx.Err()
			case <-time.After(delay):
				continue
			}
		}
		if err := tx.Commit().Error; err != nil {
			lastErr = err
			tx.Rollback()
			if !isRetryableError(err) {
				return err
			}
			delay := calculateExponentialBackoff(attempt, baseDelay)
			db.logWithLevel(db.config.Database.RetryAttemptLogLevel, "Operation %s failed (attempt %d/%d), retrying after %v: %v", "commit", attempt, maxAttempts, delay, err)
			select {
			case <-db.ctx.Done(): // Используем поле ctx
				return db.ctx.Err()
			case <-time.After(delay):
				continue
			}
		}
		return nil // Успешное выполнение
	}
	return fmt.Errorf("operation %s failed after %d attempts: %w", "transaction", maxAttempts, lastErr)
}

// Close закрывает соединение с базой данных
func (db *DB) Close() error {
	if db.sqlDB != nil {
		return db.sqlDB.Close()
	}
	return nil
}

// Ping проверяет соединение с базой данных
func (db *DB) Ping() error {
	ctx, cancel := context.WithTimeout(context.Background(), db.config.Database.ConnTimeout)
	defer cancel()
	err := db.retry("ping", db.config.Database.MaxRetries, db.config.Database.RetryDelay, func() error {
		start := time.Now()
		pingErr := db.sqlDB.PingContext(ctx)
		duration := time.Since(start).Seconds()
		status := "success"
		if pingErr != nil {
			status = "error"
		}
		metrics.DatabaseQueriesTotal.WithLabelValues("ping", status).Inc()
		logger.Logger.Debugf("Database ping attempt took %f seconds with status=%s", duration, status)
		return pingErr
	})
	if err != nil {
		return err
	}
	db.updatePoolMetrics()
	return nil
}

// Define custom type for context key
type contextKey string

const (
	startTimeKey contextKey = "start_time"
)

// gormQueryMiddleware это middleware для GORM, для логирования запросов
func gormQueryMiddleware(cfg *config.Config) func(db *gorm.DB) {
	return func(db *gorm.DB) {
		start := time.Now()
		db.Statement.Context = context.WithValue(db.Statement.Context, startTimeKey, start) // Store start time in context
		// After Hook
		db.Callback().Query().After("gorm:after_query").Register("query_metrics", func(db *gorm.DB) {
			startTime, ok := db.Statement.Context.Value(startTimeKey).(time.Time) // Retrieve start time
			if !ok {
				return // Skip if start time is not found
			}
			duration := time.Since(startTime).Seconds()
			status := "success"
			if db.Error != nil {
				status = "error"
			}
			metrics.DatabaseQueriesTotal.WithLabelValues("query", status).Inc()
			if cfg.Environment == config.Development {
				logger.Logger.Infof("SQL Query: %s| Duration: %f seconds| Rows Affected: %d| Error: %v",
					db.Dialector.Explain(db.Statement.SQL.String(), db.Statement.Vars...),
					duration,
					db.RowsAffected,
					db.Error)
			}
		})

		db.Callback().Create().After("gorm:after_create").Register("create_metrics", func(db *gorm.DB) {
			startTime, ok := db.Statement.Context.Value(startTimeKey).(time.Time) // Retrieve start time
			if !ok {
				return // Skip if start time is not found
			}
			duration := time.Since(startTime).Seconds()
			status := "success"
			if db.Error != nil {
				status = "error"
			}
			metrics.DatabaseQueriesTotal.WithLabelValues("create", status).Inc()
			if cfg.Environment == config.Development {
				logger.Logger.Infof("SQL Create: %s| Duration: %f seconds| Rows Affected: %d| Error: %v",
					db.Dialector.Explain(db.Statement.SQL.String(), db.Statement.Vars...),
					duration,
					db.RowsAffected,
					db.Error)
			}
		})

		db.Callback().Update().After("gorm:after_update").Register("update_metrics", func(db *gorm.DB) {
			startTime, ok := db.Statement.Context.Value(startTimeKey).(time.Time) // Retrieve start time
			if !ok {
				return // Skip if start time is not found
			}
			duration := time.Since(startTime).Seconds()
			status := "success"
			if db.Error != nil {
				status = "error"
			}
			metrics.DatabaseQueriesTotal.WithLabelValues("update", status).Inc()
			if cfg.Environment == config.Development {
				logger.Logger.Infof("SQL Update: %s| Duration: %f seconds| Rows Affected: %d| Error: %v",
					db.Dialector.Explain(db.Statement.SQL.String(), db.Statement.Vars...),
					duration,
					db.RowsAffected,
					db.Error)
			}
		})

		db.Callback().Delete().After("gorm:after_delete").Register("delete_metrics", func(db *gorm.DB) {
			startTime, ok := db.Statement.Context.Value(startTimeKey).(time.Time) // Retrieve start time
			if !ok {
				return // Skip if start time is not found
			}
			duration := time.Since(startTime).Seconds()
			status := "success"
			if db.Error != nil {
				status = "error"
			}
			metrics.DatabaseQueriesTotal.WithLabelValues("delete", status).Inc()
			if cfg.Environment == config.Development {
				logger.Logger.Infof("SQL Delete: %s| Duration: %f seconds| Rows Affected: %d| Error: %v",
					db.Dialector.Explain(db.Statement.SQL.String(), db.Statement.Vars...),
					duration,
					db.RowsAffected,
					db.Error)
			}
		})
	}
}
