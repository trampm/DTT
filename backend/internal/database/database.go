package database

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"math/rand"
	"time"

	"backend/internal/config"
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
	Model(value interface{}) *gorm.DB
	Where(query interface{}, args ...interface{}) *gorm.DB
	BatchCreate(ctx context.Context, values interface{}) error
	WithTransactionRetry(ctx context.Context, attempts int, delay time.Duration, fn func(tx *gorm.DB) error) error
}

// DB структура для работы с базой данных
type DB struct {
	Client *gorm.DB
	sqlDB  *sql.DB
	config *config.Config
	ctx    context.Context
}

// ConnectDB подключается к базе данных
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

	ctx, cancel := context.WithCancel(context.Background())
	dbInstance := &DB{
		Client: db,
		sqlDB:  sqlDB,
		config: cfg,
		ctx:    ctx,
	}
	dbInstance.updatePoolMetrics()
	go dbInstance.startMetricsUpdater(1 * time.Minute) // Запускаем обновление метрик каждую минуту

	logger.Logger.Info(context.Background(), fmt.Sprintf(
		"Database connected with maxOpenConns=%d, maxIdleConns=%d, connMaxLifetime=%s, connTimeout=%s, maxRetries=%d, retryDelay=%s, monitoringInterval=%s",
		cfg.Database.MaxOpenConns, cfg.Database.MaxIdleConns, cfg.Database.ConnMaxLifetime, cfg.Database.ConnTimeout, cfg.Database.MaxRetries, cfg.Database.RetryDelay, cfg.Database.MonitoringInterval,
	))

	return dbInstance, cancel
}

// updatePoolMetrics обновляет метрики пула соединений
func (db *DB) updatePoolMetrics() {
	stats := db.sqlDB.Stats()
	metrics.DatabaseOpenConnections.Set(float64(stats.OpenConnections))
	metrics.DatabaseInUseConnections.Set(float64(stats.InUse))
	metrics.DatabaseIdleConnections.Set(float64(stats.Idle))
	metrics.DatabaseWaitCount.Set(float64(stats.WaitCount))
	metrics.DatabaseWaitDuration.Set(stats.WaitDuration.Seconds())
	metrics.DatabaseMaxOpenConnections.Set(float64(stats.MaxOpenConnections))
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

// retry выполняет операцию с повторными попытками и экспоненциальной задержкой
func (db *DB) retry(operation string, attempts int, baseDelay time.Duration, fn func() error) error {
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if err := fn(); err != nil {
			lastErr = err
			if !isRetryableError(err) {
				return err
			}
			delay := calculateExponentialBackoff(attempt, baseDelay)
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

// logWithLevel логирует сообщение с указанным уровнем
func (db *DB) logWithLevel(level string, format string, args ...interface{}) {
	switch level {
	case "debug":
		logger.Logger.Debugf(format, args...)
	case "info":
		logger.Logger.Infof(format, args...)
	case "warn":
		logger.Logger.Warnf(format, args...)
	case "error":
		logger.Logger.Errorf(format, args...)
	default:
		logger.Logger.Infof(format, args...)
	}
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
	err := db.retry("ping", 3, 1*time.Second, func() error {
		start := time.Now()
		err := db.sqlDB.Ping()
		duration := time.Since(start).Seconds()
		status := "success"
		if err != nil {
			status = "error"
		}
		metrics.DatabaseQueriesTotal.WithLabelValues("ping", status).Inc()
		logger.Logger.Debugf("Database ping attempt took %f seconds with status=%s", duration, status)
		return err
	})
	if err != nil {
		return err
	}
	return nil
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

// Exec выполняет SQL запрос
func (db *DB) Exec(sql string, vars ...interface{}) *gorm.DB {
	return db.Client.Exec(sql, vars...)
}

// Save сохраняет запись в базе данных
func (db *DB) Save(value interface{}) *gorm.DB {
	return db.Client.Save(value)
}

// Preload предварительно загружает связанные данные
func (db *DB) Preload(query string, args ...interface{}) *gorm.DB {
	return db.Client.Preload(query, args...)
}

// Find находит записи, соответствующие условиям
func (db *DB) Find(dest interface{}, conds ...interface{}) *gorm.DB {
	return db.Client.Find(dest, conds...)
}

// Delete удаляет записи, соответствующие условиям
func (db *DB) Delete(value interface{}, conds ...interface{}) *gorm.DB {
	return db.Client.Delete(value, conds...)
}

// Model выбирает модель для дальнейшей работы
func (db *DB) Model(value interface{}) *gorm.DB {
	return db.Client.Model(value)
}

// Where добавляет условие WHERE к запросу
func (db *DB) Where(query interface{}, args ...interface{}) *gorm.DB {
	return db.Client.Where(query, args...)
}

// BatchCreate выполняет пакетное создание записей в одной транзакции
func (db *DB) BatchCreate(ctx context.Context, values interface{}) error {
	return db.WithTransactionRetry(ctx, db.config.Database.MaxRetries, db.config.Database.RetryDelay, func(tx *gorm.DB) error {
		result := tx.Create(values)
		if result.Error != nil {
			return fmt.Errorf("batch create failed: %w", result.Error)
		}
		logger.Logger.Debugf("Batch created %d records", result.RowsAffected)
		return nil
	})
}

// WithTransactionRetry выполняет транзакцию с повторными попытками и экспоненциальной задержкой
func (db *DB) WithTransactionRetry(ctx context.Context, attempts int, delay time.Duration, fn func(tx *gorm.DB) error) error {
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		tx := db.Client.Begin()
		if tx.Error != nil {
			lastErr = tx.Error
			tx.Rollback()
			panic(lastErr)
		}
		go func() {
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
					return
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(delay):
					continue
				}
			}
			if err := tx.Commit().Error; err != nil {
				lastErr = err
				if !isRetryableError(err) {
					return
				}
				continue
			}
			return // Успешное выполнение
		}()
	}
	return fmt.Errorf("transaction failed after %d attempts: %w", attempts, lastErr)
}
