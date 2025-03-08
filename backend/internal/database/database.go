package database

import (
	"context"
	"database/sql"
	"fmt"
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
}

// DB структура для работы с базой данных
type DB struct {
	Client GormDB
	sqlDB  *sql.DB
	config *config.Config
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
		newArgs := make([]interface{}, 0, len(args)+1)
		newArgs = append(newArgs, level)
		newArgs = append(newArgs, args...)
		logger.Logger.Warnf("Unknown log level %s, defaulting to warn: "+msg, newArgs...)
	}
}

// retry выполняет операцию с повторными попытками
func (db *DB) retry(operation string, attempts int, delay time.Duration, fn func() error) error {
	var err error
	for i := 0; i < attempts; i++ {
		err = fn()
		if err == nil {
			return nil
		}

		switch {
		case err == context.DeadlineExceeded:
			metrics.DatabaseSpecificErrors.WithLabelValues("timeout").Inc()
			db.logWithLevel(db.config.Database.TimeoutLogLevel, "Context timeout in %s after %v: %v", operation, delay*time.Duration(i), err)
		default:
			if pqErr, ok := err.(*pq.Error); ok {
				switch pqErr.Code {
				case "40001": // Serialization failure (deadlock)
					metrics.DatabaseSpecificErrors.WithLabelValues("deadlock").Inc()
					db.logWithLevel(db.config.Database.DeadlockLogLevel, "Deadlock detected in %s: %s (Code: %s)", operation, pqErr.Message, pqErr.Code)
				case "57014": // Query canceled (timeout)
					metrics.DatabaseSpecificErrors.WithLabelValues("timeout").Inc()
					db.logWithLevel(db.config.Database.TimeoutLogLevel, "Query timeout in %s: %s (Code: %s)", operation, pqErr.Message, pqErr.Code)
				}
			}
		}

		db.logWithLevel(db.config.Database.RetryAttemptLogLevel, "Attempt %d/%d failed for %s: %v", i+1, attempts, operation, err)
		metrics.DatabaseErrors.WithLabelValues(operation).Inc()
		if i < attempts-1 {
			time.Sleep(delay)
		}
	}
	return fmt.Errorf("failed after %d attempts for %s: %w", attempts, operation, err)
}

// WithTransactionRetry выполняет транзакцию с повторными попытками
func (db *DB) WithTransactionRetry(ctx context.Context, fn func(tx *gorm.DB) error) error {
	return db.retry("transaction", db.config.Database.MaxRetries, db.config.Database.RetryDelay, func() error {
		tx := db.Client.(*gorm.DB).WithContext(ctx).Begin()
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
			tx.Rollback()
			return err
		}

		if err := tx.Commit().Error; err != nil {
			return fmt.Errorf("failed to commit transaction: %w", err)
		}

		return nil
	})
}

// updatePoolMetrics обновляет метрики пула соединений
func (db *DB) updatePoolMetrics() {
	if db.sqlDB != nil {
		stats := db.sqlDB.Stats()
		metrics.DBOpenConnections.Set(float64(stats.OpenConnections))
		metrics.DBIdleConnections.Set(float64(stats.Idle))
		metrics.DBMaxOpenConnections.Set(float64(stats.MaxOpenConnections))
	}
}

// StartMonitoring запускает фоновый мониторинг состояния пула соединений
func (db *DB) StartMonitoring(ctx context.Context, interval time.Duration) {
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
					db.sqlDB.Stats().MaxOpenConnections)
			}
		}
	}()
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
				logger.Logger.Infof("SQL Query: %s | Duration: %f seconds | Rows Affected: %d | Error: %v",
					db.Dialector.Explain(db.Statement.SQL.String(), db.Statement.Vars...), duration, db.RowsAffected, db.Error)
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
				logger.Logger.Infof("SQL Create: %s | Duration: %f seconds | Rows Affected: %d | Error: %v",
					db.Dialector.Explain(db.Statement.SQL.String(), db.Statement.Vars...), duration, db.RowsAffected, db.Error)
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
				logger.Logger.Infof("SQL Update: %s | Duration: %f seconds | Rows Affected: %d | Error: %v",
					db.Dialector.Explain(db.Statement.SQL.String(), db.Statement.Vars...), duration, db.RowsAffected, db.Error)
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
				logger.Logger.Infof("SQL Delete: %s | Duration: %f seconds | Rows Affected: %d | Error: %v",
					db.Dialector.Explain(db.Statement.SQL.String(), db.Statement.Vars...), duration, db.RowsAffected, db.Error)
			}
		})
	}
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

	sqlDB.SetMaxOpenConns(cfg.Database.MaxOpenConns)
	sqlDB.SetMaxIdleConns(cfg.Database.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(cfg.Database.ConnMaxLifetime)

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Database.ConnTimeout)
	defer cancel()
	err = (&DB{config: cfg}).retry("ping", cfg.Database.MaxRetries, cfg.Database.RetryDelay, func() error {
		start := time.Now()
		pingErr := sqlDB.PingContext(ctx)
		duration := time.Since(start).Seconds()
		status := "success"
		if pingErr != nil {
			status = "error"
		}
		metrics.DatabaseQueriesTotal.WithLabelValues("ping", status).Inc()
		logger.Logger.Debugf("Database ping attempt took %f seconds", duration)
		return pingErr
	})
	if err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	dbInstance := &DB{Client: db, sqlDB: sqlDB, config: cfg}
	dbInstance.updatePoolMetrics()

	logger.Logger.Info(context.Background(), fmt.Sprintf(
		"Database connected with maxOpenConns=%d, maxIdleConns=%d, connMaxLifetime=%s, connTimeout=%s, maxRetries=%d, retryDelay=%s",
		cfg.Database.MaxOpenConns, cfg.Database.MaxIdleConns, cfg.Database.ConnMaxLifetime, cfg.Database.ConnTimeout, cfg.Database.MaxRetries, cfg.Database.RetryDelay,
	))

	return dbInstance, nil
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
	if db.sqlDB != nil {
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
		db.updatePoolMetrics()
		return err
	}
	if mockDB, ok := db.Client.(*MockDB); ok {
		return mockDB.Ping()
	}
	return fmt.Errorf("unknown database type")
}
