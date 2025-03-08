package service

import (
	"context"
	"fmt"
	"testing"
	"time"

	"backend/internal/config"
	"backend/internal/database"
	customerrors "backend/pkg/errors"
	"backend/pkg/logger"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
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

	var lastErr error
	for i := 0; i < cfg.Database.MaxRetries; i++ {
		tx := m.gormDB.WithContext(ctx).Begin()
		if tx.Error != nil {
			return tx.Error
		}

		err := fn(tx)
		if err != nil {
			tx.Rollback()
			lastErr = err
			if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "40001" {
				logger.Logger.Errorf("Deadlock detected in transaction: %s (Code: %s)", pqErr.Message, pqErr.Code)
				logger.Logger.Infof("Attempt %d/%d failed for transaction: %v", i+1, cfg.Database.MaxRetries, err)
				if i < cfg.Database.MaxRetries-1 {
					time.Sleep(cfg.Database.RetryDelay)
					continue
				}
				// Убираем return err, чтобы дойти до конца цикла
			} else {
				return err // Для не-дедлок ошибок возвращаем сразу
			}
		} else if err := tx.Commit().Error; err != nil {
			return err
		} else {
			return nil
		}
	}
	return fmt.Errorf("failed after %d attempts for transaction: %w", cfg.Database.MaxRetries, lastErr)
}

func TestRegisterUser_ExistingRole(t *testing.T) {
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

	// Настройка ожиданий для sqlMock
	sqlMock.ExpectBegin()
	sqlMock.ExpectQuery(`SELECT \* FROM "roles" WHERE name = \$1 ORDER BY "roles"."id" LIMIT \$2`).
		WithArgs("user", 1).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "description"}).
			AddRow(1, "user", "Default user role"))
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

func TestRegisterUser_DeadlockExhausted(t *testing.T) {
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

	// Настройка ожиданий для sqlMock: три попытки с дедлоком
	for i := 0; i < 3; i++ {
		sqlMock.ExpectBegin()
		sqlMock.ExpectQuery(`SELECT \* FROM "roles" WHERE name = \$1 ORDER BY "roles"."id" LIMIT \$2`).
			WithArgs("user", 1).
			WillReturnError(&pq.Error{Code: "40001", Message: "serialization failure"})
		sqlMock.ExpectRollback()
	}

	// Выполнение теста
	ctx := context.Background()
	err = authService.RegisterUser(ctx, "test@example.com", "password123")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed after 3 attempts")

	// Проверка ожиданий
	assert.NoError(t, sqlMock.ExpectationsWereMet())
}
func TestRegisterUser_UserCreationError(t *testing.T) {
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

	// Настройка ожиданий для sqlMock
	sqlMock.ExpectBegin()
	sqlMock.ExpectQuery(`SELECT \* FROM "roles" WHERE name = \$1 ORDER BY "roles"."id" LIMIT \$2`).
		WithArgs("user", 1).
		WillReturnError(gorm.ErrRecordNotFound)
	sqlMock.ExpectQuery(`INSERT INTO "roles" \("created_at","updated_at","deleted_at","name","description","parent_id"\) VALUES \(\$1,\$2,\$3,\$4,\$5,\$6\) RETURNING "id"`).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), nil, "user", "Default user role", nil).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
	sqlMock.ExpectQuery(`INSERT INTO "users" \("created_at","updated_at","deleted_at","email","password_hash","role_id"\) VALUES \(\$1,\$2,\$3,\$4,\$5,\$6\) RETURNING "id"`).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), nil, "test@example.com", sqlmock.AnyArg(), 1).
		WillReturnError(&pq.Error{Code: "23505", Message: "duplicate key value violates unique constraint"})
	sqlMock.ExpectRollback()

	// Выполнение теста
	ctx := context.Background()
	err = authService.RegisterUser(ctx, "test@example.com", "password123")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate key value")
	assert.NoError(t, sqlMock.ExpectationsWereMet())
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

	// Настройка ожиданий для sqlMock
	// Первая попытка - дедлок
	sqlMock.ExpectBegin()
	sqlMock.ExpectQuery(`SELECT \* FROM "roles" WHERE name = \$1 ORDER BY "roles"."id" LIMIT \$2`).
		WithArgs("user", 1).
		WillReturnError(&pq.Error{Code: "40001", Message: "serialization failure"})
	sqlMock.ExpectRollback()

	// Вторая попытка - успех
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

func TestAuthenticateUser_Success(t *testing.T) {
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

	// Настройка AuthService с gormDB вместо mockDB
	mockRetrier := &MockTransactionRetrier{gormDB: gormDB}
	authService := NewAuthService(gormDB, mockRetrier, "mock_dsn")

	// Подготовка данных
	email := "test@example.com"
	password := "password123"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	assert.NoError(t, err)

	// Настройка ожиданий для sqlMock
	sqlMock.ExpectQuery(`SELECT \* FROM "users" WHERE email = \$1 ORDER BY "users"."id" LIMIT \$2`).
		WithArgs(email, 1).
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "password_hash", "role_id"}).
			AddRow(1, email, string(hashedPassword), 1))

	// Выполнение теста
	user, err := authService.AuthenticateUser(email, password)
	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, email, user.Email)
	assert.Equal(t, uint(1), user.ID)

	// Проверка ожиданий
	assert.NoError(t, sqlMock.ExpectationsWereMet())
}

func TestAuthenticateUser_InvalidCredentials(t *testing.T) {
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

	// Настройка AuthService
	mockRetrier := &MockTransactionRetrier{gormDB: gormDB}
	authService := NewAuthService(gormDB, mockRetrier, "mock_dsn")

	// Подготовка данных
	email := "test@example.com"
	password := "password123"
	wrongPassword := "wrongpassword"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	assert.NoError(t, err)

	// Настройка ожиданий для sqlMock
	sqlMock.ExpectQuery(`SELECT \* FROM "users" WHERE email = \$1 ORDER BY "users"."id" LIMIT \$2`).
		WithArgs(email, 1).
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "password_hash", "role_id"}).
			AddRow(1, email, string(hashedPassword), 1))

	// Выполнение теста с неверным паролем
	user, err := authService.AuthenticateUser(email, wrongPassword)
	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Equal(t, customerrors.ErrInvalidCredentials, err)

	// Проверка ожиданий
	assert.NoError(t, sqlMock.ExpectationsWereMet())
}

func TestAuthenticateUser_UserNotFound(t *testing.T) {
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

	// Настройка AuthService
	mockRetrier := &MockTransactionRetrier{gormDB: gormDB}
	authService := NewAuthService(gormDB, mockRetrier, "mock_dsn")

	// Подготовка данных
	email := "nonexistent@example.com"
	password := "password123"

	// Настройка ожиданий для sqlMock
	sqlMock.ExpectQuery(`SELECT \* FROM "users" WHERE email = \$1 ORDER BY "users"."id" LIMIT \$2`).
		WithArgs(email, 1).
		WillReturnError(gorm.ErrRecordNotFound)

	// Выполнение теста
	user, err := authService.AuthenticateUser(email, password)
	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Equal(t, customerrors.ErrUserNotFound, err)

	// Проверка ожиданий
	assert.NoError(t, sqlMock.ExpectationsWereMet())
}

func TestGenerateRefreshToken_Success(t *testing.T) {
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

	// Настройка AuthService
	mockRetrier := &MockTransactionRetrier{gormDB: gormDB}
	authService := NewAuthService(gormDB, mockRetrier, "mock_dsn")

	// Подготовка данных
	userID := uint(1)
	ipAddress := "127.0.0.1"       // Заглушка IP-адреса
	userAgent := "Test User Agent" // Заглушка User-Agent

	// Настройка ожиданий для sqlMock
	sqlMock.ExpectBegin()
	sqlMock.ExpectQuery(`INSERT INTO "refresh_tokens" \("created_at","updated_at","deleted_at","user_id","token","expires_at","ip_address","user_agent"\) VALUES \(\$1,\$2,\$3,\$4,\$5,\$6,\$7,\$8\) RETURNING "id"`).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), nil, userID, sqlmock.AnyArg(), sqlmock.AnyArg(), ipAddress, userAgent).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
	sqlMock.ExpectCommit()

	// Выполнение теста
	ctx := context.Background()
	token, err := authService.GenerateRefreshToken(ctx, userID, ipAddress, userAgent)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.Equal(t, 36, len(token)) // UUID length

	// Проверка ожиданий
	assert.NoError(t, sqlMock.ExpectationsWereMet())
}

func TestValidateRefreshToken_Success(t *testing.T) {
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
	mockRetrier := &MockTransactionRetrier{gormDB: gormDB}

	// Настройка AuthService
	authService := NewAuthService(gormDB, mockRetrier, "mock_dsn")

	// Подготовка данных
	userID := uint(1)
	token := "550e8400-e29b-41d4-a716-446655440000" // Пример UUID
	expiresAt := time.Now().Add(24 * time.Hour)

	// Настройка ожиданий для sqlMock
	sqlMock.ExpectQuery(`SELECT \* FROM "refresh_tokens" WHERE token = \$1 ORDER BY "refresh_tokens"."id" LIMIT \$2`).
		WithArgs(token, 1).
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "token", "expires_at"}).
			AddRow(1, userID, token, expiresAt))

	// Выполнение теста
	returnedUserID, err := authService.ValidateRefreshToken(token)
	assert.NoError(t, err)
	assert.Equal(t, userID, returnedUserID)

	// Проверка ожиданий
	assert.NoError(t, sqlMock.ExpectationsWereMet())
}

func TestValidateRefreshToken_Expired(t *testing.T) {
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

	// Настройка AuthService
	mockRetrier := &MockTransactionRetrier{gormDB: gormDB}
	authService := NewAuthService(gormDB, mockRetrier, "mock_dsn")

	// Подготовка данных
	userID := uint(1)
	token := "550e8400-e29b-41d4-a716-446655440000" // Пример UUID
	expiresAt := time.Now().Add(-24 * time.Hour)    // Истёкший токен

	// Настройка ожиданий для sqlMock
	sqlMock.ExpectQuery(`SELECT \* FROM "refresh_tokens" WHERE token = \$1 ORDER BY "refresh_tokens"."id" LIMIT \$2`).
		WithArgs(token, 1).
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "token", "expires_at"}).
			AddRow(1, userID, token, expiresAt))

	// Выполнение теста
	returnedUserID, err := authService.ValidateRefreshToken(token)
	assert.Error(t, err)
	assert.Equal(t, uint(0), returnedUserID)
	assert.Equal(t, customerrors.ErrInvalidToken, err)

	// Проверка ожиданий
	assert.NoError(t, sqlMock.ExpectationsWereMet())
}
func TestValidateRefreshToken_NotFound(t *testing.T) {
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

	// Настройка AuthService
	mockRetrier := &MockTransactionRetrier{gormDB: gormDB}
	authService := NewAuthService(gormDB, mockRetrier, "mock_dsn")

	// Подготовка данных
	token := "550e8400-e29b-41d4-a716-446655440000" // Пример UUID

	// Настройка ожиданий для sqlMock
	sqlMock.ExpectQuery(`SELECT \* FROM "refresh_tokens" WHERE token = \$1 ORDER BY "refresh_tokens"."id" LIMIT \$2`).
		WithArgs(token, 1).
		WillReturnError(gorm.ErrRecordNotFound)

	// Выполнение теста
	returnedUserID, err := authService.ValidateRefreshToken(token)
	assert.Error(t, err)
	assert.Equal(t, uint(0), returnedUserID)
	assert.Equal(t, customerrors.ErrInvalidToken, err)

	// Проверка ожиданий
	assert.NoError(t, sqlMock.ExpectationsWereMet())
}
func TestRevokeRefreshToken_Success(t *testing.T) {
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

	// Настройка AuthService
	mockRetrier := &MockTransactionRetrier{gormDB: gormDB}
	authService := NewAuthService(gormDB, mockRetrier, "mock_dsn")

	// Подготовка данных
	token := "550e8400-e29b-41d4-a716-446655440000" // Пример UUID

	// Настройка ожиданий для sqlMock
	sqlMock.ExpectBegin()
	sqlMock.ExpectExec(`DELETE FROM "refresh_tokens" WHERE token = \$1`).
		WithArgs(token).
		WillReturnResult(sqlmock.NewResult(1, 1))
	sqlMock.ExpectCommit()

	// Выполнение теста
	ctx := context.Background()
	err = authService.RevokeRefreshToken(ctx, token)
	assert.NoError(t, err)

	// Проверка ожиданий
	assert.NoError(t, sqlMock.ExpectationsWereMet())
}
func TestRevokeRefreshToken_NotFound(t *testing.T) {
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

	// Настройка AuthService
	mockRetrier := &MockTransactionRetrier{gormDB: gormDB}
	authService := NewAuthService(gormDB, mockRetrier, "mock_dsn")

	// Подготовка данных
	token := "550e8400-e29b-41d4-a716-446655440000" // Пример UUID

	// Настройка ожиданий для sqlMock
	sqlMock.ExpectBegin()
	sqlMock.ExpectExec(`DELETE FROM "refresh_tokens" WHERE token = \$1`).
		WithArgs(token).
		WillReturnResult(sqlmock.NewResult(0, 0)) // 0 строк удалено
	sqlMock.ExpectCommit()

	// Выполнение теста
	ctx := context.Background()
	err = authService.RevokeRefreshToken(ctx, token)
	assert.NoError(t, err) // Предполагаем, что отсутствие токена не считается ошибкой

	// Проверка ожиданий
	assert.NoError(t, sqlMock.ExpectationsWereMet())
}
func TestRegisterUser_InvalidEmail(t *testing.T) {
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

	// Настройка AuthService
	mockRetrier := &MockTransactionRetrier{gormDB: gormDB}
	authService := NewAuthService(gormDB, mockRetrier, "mock_dsn")

	// Подготовка данных с некорректным email
	invalidEmail := "invalid-email"
	password := "password123"

	// Выполнение теста
	ctx := context.Background()
	err = authService.RegisterUser(ctx, invalidEmail, password)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid email format")

	// Проверка, что запросы к базе не выполнялись
	assert.NoError(t, sqlMock.ExpectationsWereMet())
}
func TestAuthenticateUser_InvalidEmail(t *testing.T) {
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

	// Настройка AuthService
	mockRetrier := &MockTransactionRetrier{gormDB: gormDB}
	authService := NewAuthService(gormDB, mockRetrier, "mock_dsn")

	// Подготовка данных с некорректным email
	invalidEmail := "invalid-email"
	password := "password123"

	// Выполнение теста
	_, err = authService.AuthenticateUser(invalidEmail, password)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid email format")

	// Проверка, что запросы к базе не выполнялись
	assert.NoError(t, sqlMock.ExpectationsWereMet())
}

func TestInitiatePasswordReset_InvalidEmail(t *testing.T) {
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

	// Настройка AuthService
	mockRetrier := &MockTransactionRetrier{gormDB: gormDB}
	authService := NewAuthService(gormDB, mockRetrier, "mock_dsn")

	// Подготовка данных с некорректным email
	invalidEmail := "invalid-email"

	// Выполнение теста
	ctx := context.Background()
	err = authService.InitiatePasswordReset(ctx, invalidEmail)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid email format")

	// Проверка, что запросы к базе не выполнялись
	assert.NoError(t, sqlMock.ExpectationsWereMet())
}

func TestInitiatePasswordReset_Success(t *testing.T) {
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

	// Настройка AuthService
	mockRetrier := &MockTransactionRetrier{gormDB: gormDB}
	authService := NewAuthService(gormDB, mockRetrier, "mock_dsn")

	// Подготовка данных
	email := "test@example.com"
	userID := uint(1)

	// Настройка ожиданий для sqlMock
	sqlMock.ExpectBegin()
	sqlMock.ExpectQuery(`SELECT \* FROM "users" WHERE email = \$1 ORDER BY "users"."id" LIMIT \$2`).
		WithArgs(email, 1).
		WillReturnRows(sqlmock.NewRows([]string{"id", "email"}).
			AddRow(userID, email))
	sqlMock.ExpectQuery(`INSERT INTO "password_resets" \("created_at","updated_at","deleted_at","user_id","token","expires_at","used"\) VALUES \(\$1,\$2,\$3,\$4,\$5,\$6,\$7\) RETURNING "id"`).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), nil, userID, sqlmock.AnyArg(), sqlmock.AnyArg(), false).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
	sqlMock.ExpectCommit()

	// Выполнение теста
	ctx := context.Background()
	err = authService.InitiatePasswordReset(ctx, email)
	assert.NoError(t, err)

	// Проверка ожиданий
	assert.NoError(t, sqlMock.ExpectationsWereMet())
}

func TestInitiatePasswordReset_UserNotFound(t *testing.T) {
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

	// Настройка AuthService
	mockRetrier := &MockTransactionRetrier{gormDB: gormDB}
	authService := NewAuthService(gormDB, mockRetrier, "mock_dsn")

	// Подготовка данных
	email := "nonexistent@example.com"

	// Настройка ожиданий для sqlMock
	sqlMock.ExpectBegin()
	sqlMock.ExpectQuery(`SELECT \* FROM "users" WHERE email = \$1 ORDER BY "users"."id" LIMIT \$2`).
		WithArgs(email, 1).
		WillReturnError(gorm.ErrRecordNotFound)
	sqlMock.ExpectCommit()

	// Выполнение теста
	ctx := context.Background()
	err = authService.InitiatePasswordReset(ctx, email)
	assert.NoError(t, err)

	// Проверка ожиданий
	assert.NoError(t, sqlMock.ExpectationsWereMet())
}

func TestResetPassword_Success(t *testing.T) {
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

	// Настройка AuthService
	mockRetrier := &MockTransactionRetrier{gormDB: gormDB}
	authService := NewAuthService(gormDB, mockRetrier, "mock_dsn")

	// Подготовка данных
	token := "550e8400-e29b-41d4-a716-446655440000"
	userID := uint(1)
	newPassword := "newpassword123"
	expiresAt := time.Now().Add(1 * time.Hour)

	// Настройка ожиданий для sqlMock
	sqlMock.ExpectBegin()
	sqlMock.ExpectQuery(`SELECT \* FROM "password_resets" WHERE token = \$1 AND used = false ORDER BY "password_resets"."id" LIMIT \$2`).
		WithArgs(token, 1).
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "token", "expires_at", "used"}).
			AddRow(1, userID, token, expiresAt, false))
	sqlMock.ExpectExec(`UPDATE "users" SET "password_hash"=\$1,"updated_at"=\$2 WHERE id = \$3`). // Обновлено
													WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), userID). // Обновлено
													WillReturnResult(sqlmock.NewResult(1, 1))
	sqlMock.ExpectExec(`UPDATE "password_resets" SET "created_at"=\$1,"updated_at"=\$2,"deleted_at"=\$3,"user_id"=\$4,"token"=\$5,"expires_at"=\$6,"used"=\$7 WHERE "id" = \$8`). //Изменено
																							WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), nil, userID, token, expiresAt, true, 1). //Изменено
																							WillReturnResult(sqlmock.NewResult(1, 1))
	sqlMock.ExpectCommit()

	// Выполнение теста
	ctx := context.Background()
	err = authService.ResetPassword(ctx, token, newPassword)
	assert.NoError(t, err)

	// Проверка ожиданий
	assert.NoError(t, sqlMock.ExpectationsWereMet())
}
