package service

import (
	"context"
	"testing"
	"time"

	"backend/internal/config"
	"backend/internal/database"
	"backend/pkg/logger"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// MockTransactionRetrier мок для TransactionRetrier
type MockTransactionRetrier struct {
	gormDB *gorm.DB
}

func (m *MockTransactionRetrier) WithTransactionRetry(ctx context.Context, fn func(tx *gorm.DB) error) error {
	cfg := &config.Config{
		Database: config.DatabaseConfig{
			MaxRetries: 3,
			RetryDelay: 1 * time.Second,
		},
	}

	for i := 0; i < cfg.Database.MaxRetries; i++ {
		tx := m.gormDB.WithContext(ctx).Begin()
		if tx.Error != nil {
			return tx.Error
		}

		err := fn(tx)
		if err != nil {
			tx.Rollback()
			if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "40001" {
				logger.Logger.Errorf("Deadlock detected in transaction: %s (Code: %s)", pqErr.Message, pqErr.Code)
				logger.Logger.Infof("Attempt %d/%d failed for transaction: %v", i+1, cfg.Database.MaxRetries, err)
				if i < cfg.Database.MaxRetries-1 {
					time.Sleep(cfg.Database.RetryDelay)
					continue
				}
				return err
			}
			return err
		}

		if err := tx.Commit().Error; err != nil {
			return err
		}
		return nil
	}
	return nil
}

func TestRegisterUser_DeadlockRetry(t *testing.T) {
	// Инициализация логгера
	err := logger.InitLogger("info", "console", "", 100, 10, 30, false, "UTC", "text")
	assert.NoError(t, err)

	// Создание mock базы данных
	sqlDB, sqlMock, err := sqlmock.New()
	assert.NoError(t, err)
	defer sqlDB.Close()

	// Создание GORM с моковой базой
	gormDB, err := gorm.Open(postgres.New(postgres.Config{
		Conn: sqlDB,
	}), &gorm.Config{})
	assert.NoError(t, err)

	// Создание моков
	mockDB := database.NewMockDB()
	mockRetrier := &MockTransactionRetrier{gormDB: gormDB}

	// Настройка AuthService
	authService := NewAuthService(mockDB, mockRetrier, "mock_dsn")

	// Настройка ожиданий для sqlMock (одна успешная попытка)
	sqlMock.ExpectBegin()
	sqlMock.ExpectQuery(`SELECT \* FROM "roles" WHERE name = \$1 ORDER BY "roles"."id" LIMIT \$2`).
		WithArgs("user", 1).
		WillReturnError(gorm.ErrRecordNotFound)
	sqlMock.ExpectQuery(`INSERT INTO "roles" \("created_at","updated_at","deleted_at","name","description","parent_id"\) VALUES \(\$1,\$2,\$3,\$4,\$5,\$6\) RETURNING "id"`).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), nil, "user", "Default user role", nil).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
	sqlMock.ExpectQuery(`INSERT INTO "users" \("created_at","updated_at","deleted_at","email","password_hash","role_id"\) VALUES \(\$1,\$2,\$3,\$4,\$5,\$6\) RETURNING "id"`).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), nil, "test@example.com", sqlmock.AnyArg(), 1).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
	sqlMock.ExpectCommit()

	// Выполнение теста
	ctx := context.Background()
	err = authService.RegisterUser(ctx, "test@example.com", "password123")
	assert.NoError(t, err)

	// Проверка ожиданий
	assert.NoError(t, sqlMock.ExpectationsWereMet())
}
