package service

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"backend/internal/auth/models"
	customerrors "backend/pkg/errors" // Import custom errors package
	"backend/pkg/logger"
	"errors"
)

type AuthServiceInterface interface {
	RegisterUser(ctx context.Context, email, password string) error
	AuthenticateUser(email, password string) (*models.User, error)
	InitializeDatabase() error
	CreateRole(ctx context.Context, name, description string) (*models.Role, error)
	CreatePermission(ctx context.Context, name, description string) (*models.Permission, error)
	AssignRoleToUser(ctx context.Context, userID, roleID uint) error
	AssignPermissionToRole(ctx context.Context, roleID, permissionID uint) error
	GetUserWithRole(email string) (*models.User, error)
	GetUserWithRoleByID(userID uint) (*models.User, error)
	GenerateRefreshToken(ctx context.Context, userID uint, ipAddress string, userAgent string) (string, error)
	ValidateRefreshToken(token string) (uint, error)
	RevokeRefreshToken(ctx context.Context, token string) error
	GetRolePermissionsRecursive(roleID uint) ([]string, error)
	GetProfile(userID uint) (*models.ProfileResponse, error)
	UpdateProfile(ctx context.Context, userID uint, update *models.UpdateProfileRequest) error
	UpdateAvatar(ctx context.Context, userID uint, avatarURL string) error
	InitiatePasswordReset(ctx context.Context, email string) error
	ValidateResetToken(token string) error
	ResetPassword(ctx context.Context, token string, newPassword string) error
	DB() DB
}

type DB interface {
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

// TransactionRetrier интерфейс для выполнения транзакций с повторными попытками
type TransactionRetrier interface {
	WithTransactionRetry(ctx context.Context, fn func(tx *gorm.DB) error) error
}

type AuthService struct {
	db    DB
	dbRaw TransactionRetrier
	cache sync.Map
	dsn   string
}

type cachedPermissions struct {
	Permissions []string
	ExpiresAt   time.Time
}

type cachedProfile struct {
	Profile   *models.ProfileResponse
	ExpiresAt time.Time
}

const (
	cacheTTL = 5 * time.Minute
)

var _ AuthServiceInterface = (*AuthService)(nil)

// NewAuthService инициализирует сервис с кэшем и запускает очистку кэша
func NewAuthService(db DB, dbRaw TransactionRetrier, dsn string) AuthServiceInterface {
	s := &AuthService{
		db:    db,
		dbRaw: dbRaw,
		cache: sync.Map{},
		dsn:   dsn,
	}
	s.startCacheCleaner()
	return s
}

func (s *AuthService) DB() DB {
	return s.db
}

// startCacheCleaner запускает фоновую очистку устаревших записей кэша
func (s *AuthService) startCacheCleaner() {
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			s.cache.Range(func(key, value interface{}) bool {
				switch v := value.(type) {
				case cachedPermissions:
					if time.Now().After(v.ExpiresAt) {
						s.cache.Delete(key)
					}
				case cachedProfile:
					if time.Now().After(v.ExpiresAt) {
						s.cache.Delete(key)
					}
				}
				return true
			})
		}
	}()
}

func (s *AuthService) hashPassword(password string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		logger.Logger.Errorf("failed to hash password: %v", err)
		return "", customerrors.WrapError(err, "token_creation_error", "Failed to hash password")
	}
	return string(hashedBytes), nil
}

func (s *AuthService) comparePasswords(hashedPassword, password string) error {
	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)); err != nil {
		logger.Logger.Infof("password mismatch: %v", err)
		return customerrors.WrapError(customerrors.ErrInvalidCredentials, "invalid_credentials", "Password mismatch")
	}
	return nil
}

// InitializeDatabase инициализирует базу данных
func (s *AuthService) InitializeDatabase() error {
	ctx := context.Background() // Создаем контекст
	logger.Logger.Info(context.Background(), "Starting database initialization")

	if err := s.db.Exec("SELECT 1").Error; err != nil {
		logger.Logger.Errorf("Database connection check failed: %v", err)
		return fmt.Errorf("failed to verify database connection: %w", err)
	}

	migrationPath := "file://./migrations"
	logger.Logger.Infof("Initializing migrations with DSN: %s and path: %s", s.dsn, migrationPath)
	m, err := migrate.New(migrationPath, s.dsn)
	if err != nil {
		logger.Logger.Errorf("Failed to initialize migrations: %v", err)
		return fmt.Errorf("failed to initialize migrations: %w", err)
	}

	err = m.Up()
	if err != nil {
		if err == migrate.ErrNoChange {
			logger.Logger.Infof("No new migrations to apply")
		} else {
			logger.Logger.Errorf("Failed to apply migrations: %v", err)
			return fmt.Errorf("failed to apply migrations: %w", err)
		}
	}

	logger.Logger.Info(ctx, "Database migrations applied successfully")

	if err := s.createAdminUserIfNotExists(); err != nil {
		logger.Logger.Errorf("Failed to create admin user: %v", err)
		return err
	}

	logger.Logger.Info(ctx, "Database initialization completed successfully")
	return nil
}

func (s *AuthService) createAdminUserIfNotExists() error {
	ctx := context.Background() // Создаем контекст
	return s.dbRaw.WithTransactionRetry(ctx, func(tx *gorm.DB) error {
		var user models.User
		if err := tx.First(&user, "email = ?", "admin@example.com").Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				//return s.handleDBError("find admin user", err)
				return fmt.Errorf("find admin user:%w", customerrors.WrapError(err, "not_found", "Admin user not found"))
			}

			hashedPassword, err := s.hashPassword("admin")
			if err != nil {
				return fmt.Errorf("hash password:%w", err)
			}

			var adminRole models.Role
			if err := tx.First(&adminRole, "name = ?", "admin").Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					adminRole = models.Role{
						Name:        "admin",
						Description: "Administrator with full access",
					}
					if err := tx.Create(&adminRole).Error; err != nil {
						return fmt.Errorf("create admin role:%w", customerrors.WrapError(err, "database_error", "Failed to create admin role"))
					}
				} else {
					//return s.handleDBError("find admin role", err)
					return fmt.Errorf("find admin role:%w", customerrors.WrapError(err, "database_error", "Failed to find admin role"))
				}
			}

			adminUser := &models.User{
				Email:        "admin@example.com",
				PasswordHash: hashedPassword,
				RoleID:       &adminRole.ID,
			}

			if err := tx.Create(adminUser).Error; err != nil {
				//return s.handleDBError("create admin user", tx.Create(adminUser).Error)
				return fmt.Errorf("create admin user:%w", customerrors.WrapError(err, "database_error", "Failed to create admin user"))
			}
		}
		return nil
	})
}

func (s *AuthService) RegisterUser(ctx context.Context, email, password string) error {
	user := models.User{
		Email: email,
	}
	if err := user.Validate(); err != nil {
		logger.Logger.Errorf("Invalid user data: %v", err)
		return fmt.Errorf("registration failed: %w", err)
	}

	return s.dbRaw.WithTransactionRetry(ctx, func(tx *gorm.DB) error {
		var defaultRole models.Role
		if err := tx.First(&defaultRole, "name = ?", "user").Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				logger.Logger.Infof("Role 'user' not found, creating new role")
				defaultRole = models.Role{
					Name:        "user",
					Description: "Default user role",
				}
				if err := tx.Create(&defaultRole).Error; err != nil {
					return fmt.Errorf("create default user role: %w", err)
				}
				logger.Logger.Infof("Role 'user' created successfully")
			} else {
				return fmt.Errorf("find default user role: %w", err)
			}
		} else {
			logger.Logger.Infof("Role 'user' found")
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash password: %w", err)
		}

		user.PasswordHash = string(hashedPassword)
		user.RoleID = &defaultRole.ID
		if err := tx.Create(&user).Error; err != nil {
			// Если пользователь не создан, удаляем созданную роль
			if defaultRole.ID != 0 {
				logger.Logger.Warnf("Deleting partially created role 'user'")
				if delErr := tx.Delete(&defaultRole).Error; delErr != nil {
					logger.Logger.Errorf("Failed to delete partially created role: %v", delErr)
				}
			}
			return fmt.Errorf("create user: %w", err)
		}
		logger.Logger.Infof("User created successfully")

		return nil
	})
}

func (s *AuthService) GetUserByEmail(email string) (*models.User, error) {
	var user models.User
	if err := s.db.First(&user, "email = ?", email).Error; err != nil {
		//return nil, s.handleDBError("find user", err)
		return nil, fmt.Errorf("find user:%w", customerrors.WrapError(err, "database_error", "Failed to find user"))
	}
	return &user, nil
}

// AuthenticateUser аутентифицирует пользователя
func (s *AuthService) AuthenticateUser(email, password string) (*models.User, error) {
	user := &models.User{
		Email: email,
	}
	if err := user.Validate(); err != nil {
		logger.Logger.Errorf("Invalid email format: %v", err)
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	result := s.db.First(user, "email = ?", email)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, customerrors.ErrUserNotFound
		}
		return nil, customerrors.ErrDatabaseConnection
	}

	if err := s.comparePasswords(user.PasswordHash, password); err != nil {
		return nil, err
	}

	return user, nil
}

// CreateRole создаёт роль
func (s *AuthService) CreateRole(ctx context.Context, name, description string) (*models.Role, error) {
	var role *models.Role
	err := s.dbRaw.WithTransactionRetry(ctx, func(tx *gorm.DB) error {
		role = &models.Role{
			Name:        name,
			Description: description,
		}
		if err := tx.Create(role).Error; err != nil {
			//return s.handleDBError("create role", err)
			return fmt.Errorf("create role:%w", customerrors.WrapError(err, "database_error", "Failed to create role"))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return role, nil
}

// CreatePermission создаёт разрешение
func (s *AuthService) CreatePermission(ctx context.Context, name, description string) (*models.Permission, error) {
	var permission *models.Permission
	err := s.dbRaw.WithTransactionRetry(ctx, func(tx *gorm.DB) error {
		permission = &models.Permission{
			Name:        name,
			Description: description,
		}
		if err := tx.Create(permission).Error; err != nil {
			//return s.handleDBError("create permission", err)
			return fmt.Errorf("create permission:%w", customerrors.WrapError(err, "database_error", "Failed to create permission"))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return permission, nil
}

// AssignRoleToUser назначает роль пользователю с использованием транзакции
func (s *AuthService) AssignRoleToUser(ctx context.Context, userID, roleID uint) error {
	return s.dbRaw.WithTransactionRetry(ctx, func(tx *gorm.DB) error {
		var user models.User
		if err := tx.First(&user, "id = ?", userID).Error; err != nil {
			//return s.handleDBError("find user for role assignment", err)
			return fmt.Errorf("find user for role assignment:%w", customerrors.WrapError(err, "not_found", "Failed to find user for role assignment"))
		}

		var role models.Role
		if err := tx.First(&role, "id = ?", roleID).Error; err != nil {
			//return s.handleDBError("find role for assignment", err)
			return fmt.Errorf("find role for assignment:%w", customerrors.WrapError(err, "not_found", "Failed to find role for assignment"))
		}

		user.RoleID = &roleID
		if err := tx.Save(&user).Error; err != nil {
			//return s.handleDBError("assign role to user", err)
			return fmt.Errorf("assign role to user:%w", customerrors.WrapError(err, "database_error", "Failed to assign role to user"))
		}
		return nil
	})
}

// AssignPermissionToRole назначает разрешение роли с использованием транзакции
func (s *AuthService) AssignPermissionToRole(ctx context.Context, roleID, permissionID uint) error {
	return s.dbRaw.WithTransactionRetry(ctx, func(tx *gorm.DB) error {
		rolePermission := &models.RolePermission{
			RoleID:       roleID,
			PermissionID: permissionID,
		}
		if err := tx.Create(rolePermission).Error; err != nil {
			//return s.handleDBError("assign permission to role", err)
			return fmt.Errorf("assign permission to role:%w", customerrors.WrapError(err, "database_error", "Failed to assign permission to role"))
		}
		return nil
	})
}

// GetUserWithRole получает пользователя с ролью
func (s *AuthService) GetUserWithRole(email string) (*models.User, error) {
	var user models.User
	if err := s.db.Preload("Role").First(&user, "email = ?", email).Error; err != nil {
		//return nil, s.handleDBError("find user with role", err)
		return nil, fmt.Errorf("find user with role:%w", customerrors.WrapError(err, "database_error", "Failed to find user with role"))
	}
	return &user, nil
}

func (s *AuthService) GetUserWithRoleByID(userID uint) (*models.User, error) {
	var user models.User
	if err := s.db.Preload("Role").First(&user, "id = ?", userID).Error; err != nil {
		//return nil, s.handleDBError("find user with role by id", err)
		return nil, fmt.Errorf("find user with role by id:%w", customerrors.WrapError(err, "database_error", "Failed to find user with role by id"))
	}
	return &user, nil
}

// GetRolePermissionsRecursive рекурсивно собирает все права роли, включая унаследованные, с использованием кэша
func (s *AuthService) GetRolePermissionsRecursive(roleID uint) ([]string, error) {
	cacheKey := fmt.Sprintf("role:%d", roleID)
	if cached, ok := s.cache.Load(cacheKey); ok {
		cachedPerms := cached.(cachedPermissions)
		if time.Now().Before(cachedPerms.ExpiresAt) {
			return cachedPerms.Permissions, nil
		}
		s.cache.Delete(cacheKey)
	}

	var permissions []string
	visited := make(map[uint]bool)

	var collectPermissions func(id uint) error
	collectPermissions = func(id uint) error {
		if visited[id] {
			return nil
		}
		visited[id] = true

		var rolePermissions []models.RolePermission
		if err := s.db.Find(&rolePermissions, "role_id = ?", id).Error; err != nil {
			//return s.handleDBError("find role permissions", err)
			return fmt.Errorf("find role permissions:%w", customerrors.WrapError(err, "database_error", "Failed to find role permissions"))
		}

		for _, rp := range rolePermissions {
			var perm models.Permission
			if err := s.db.First(&perm, "id = ?", rp.PermissionID).Error; err == nil {
				permissions = append(permissions, perm.Name)
			}
		}

		var role models.Role
		if err := s.db.First(&role, "id = ?", id).Error; err != nil {
			//return s.handleDBError("find role", err)
			return fmt.Errorf("find role:%w", customerrors.WrapError(err, "database_error", "Failed to find role"))
		}

		if role.ParentID != nil {
			if err := collectPermissions(*role.ParentID); err != nil {
				return err
			}
		}

		return nil
	}

	if err := collectPermissions(roleID); err != nil {
		return nil, err
	}

	uniquePermissions := make([]string, 0, len(permissions))
	seen := make(map[string]bool)
	for _, perm := range permissions {
		if !seen[perm] {
			seen[perm] = true
			uniquePermissions = append(uniquePermissions, perm)
		}
	}

	s.cache.Store(cacheKey, cachedPermissions{
		Permissions: uniquePermissions,
		ExpiresAt:   time.Now().Add(cacheTTL),
	})

	return uniquePermissions, nil
}

// GenerateRefreshToken генерирует новый refresh-токен с использованием транзакции
func (s *AuthService) GenerateRefreshToken(ctx context.Context, userID uint, ipAddress string, userAgent string) (string, error) {
	var token string
	err := s.dbRaw.WithTransactionRetry(ctx, func(tx *gorm.DB) error {
		token = uuid.New().String()
		expiresAt := time.Now().Add(7 * 24 * time.Hour)

		refreshToken := &models.RefreshToken{
			UserID:    userID,
			Token:     token,
			ExpiresAt: expiresAt,
			IPAddress: ipAddress, // store the client IP
			UserAgent: userAgent, // store the client user agent
		}

		if err := tx.Create(refreshToken).Error; err != nil {
			//return s.handleDBError("create refresh token", err)
			return fmt.Errorf("create refresh token:%w", customerrors.WrapError(err, "database_error", "Failed to create refresh token"))
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

// ValidateRefreshToken проверяет refresh-токен и возвращает userID
func (s *AuthService) ValidateRefreshToken(token string) (uint, error) {
	var refreshToken models.RefreshToken
	_, err := s.validateToken(&refreshToken, token)
	if err != nil {
		return 0, err
	}
	return refreshToken.UserID, nil
}

// RevokeRefreshToken удаляет refresh-токен с использованием транзакции
func (s *AuthService) RevokeRefreshToken(ctx context.Context, token string) error {
	return s.dbRaw.WithTransactionRetry(ctx, func(tx *gorm.DB) error {
		if err := tx.Delete(&models.RefreshToken{}, "token = ?", token).Error; err != nil {
			//return s.handleDBError("revoke refresh token", err)
			return fmt.Errorf("revoke refresh token:%w", customerrors.WrapError(err, "database_error", "Failed to revoke refresh token"))
		}
		return nil
	})
}

func (s *AuthService) GetProfile(userID uint) (*models.ProfileResponse, error) {
	cacheKey := fmt.Sprintf("profile:%d", userID)
	if cached, ok := s.cache.Load(cacheKey); ok {
		cachedProfile := cached.(cachedProfile)
		if time.Now().Before(cachedProfile.ExpiresAt) {
			return cachedProfile.Profile, nil
		}
		s.cache.Delete(cacheKey)
	}

	var user models.User
	if err := s.db.Preload("Role").Preload("Profile").First(&user, userID).Error; err != nil {
		//return nil, s.handleDBError("get user profile", err)
		return nil, fmt.Errorf("get user profile:%w", customerrors.WrapError(err, "database_error", "Failed to get user profile"))
	}

	response := &models.ProfileResponse{
		ID:    user.ID,
		Email: user.Email,
		Role:  user.Role.Name,
	}

	if user.Profile != nil {
		response.FirstName = user.Profile.FirstName
		response.LastName = user.Profile.LastName
		response.PhoneNumber = user.Profile.PhoneNumber
		response.Bio = user.Profile.Bio
		response.Avatar = user.Profile.Avatar
	}

	s.cache.Store(cacheKey, cachedProfile{
		Profile:   response,
		ExpiresAt: time.Now().Add(cacheTTL),
	})

	return response, nil
}

// UpdateProfile обновляет профиль пользователя с использованием транзакции
func (s *AuthService) UpdateProfile(ctx context.Context, userID uint, update *models.UpdateProfileRequest) error {
	return s.dbRaw.WithTransactionRetry(ctx, func(tx *gorm.DB) error {
		var profile models.Profile
		err := tx.FirstOrCreate(&profile, models.Profile{UserID: userID}).Error
		if err != nil {
			//return s.handleDBError("get or create profile", err)
			return fmt.Errorf("get or create profile:%w", customerrors.WrapError(err, "database_error", "Failed to get or create profile"))
		}

		profile.FirstName = update.FirstName
		profile.LastName = update.LastName
		profile.PhoneNumber = update.PhoneNumber
		profile.Bio = update.Bio

		if err := tx.Save(&profile).Error; err != nil {
			//return s.handleDBError("update profile", err)
			return fmt.Errorf("update profile:%w", customerrors.WrapError(err, "database_error", "Failed to update profile"))
		}

		// Очистка кэша после обновления
		cacheKey := fmt.Sprintf("profile:%d", userID)
		s.cache.Delete(cacheKey)

		return nil
	})
}

// UpdateAvatar обновляет аватар пользователя с использованием транзакции
func (s *AuthService) UpdateAvatar(ctx context.Context, userID uint, avatarURL string) error {
	return s.dbRaw.WithTransactionRetry(ctx, func(tx *gorm.DB) error {
		var profile models.Profile
		err := tx.FirstOrCreate(&profile, models.Profile{UserID: userID}).Error
		if err != nil {
			//return s.handleDBError("get or create profile", err)
			return fmt.Errorf("get or create profile:%w", customerrors.WrapError(err, "database_error", "Failed to get or create profile"))
		}

		profile.Avatar = avatarURL
		if err := tx.Save(&profile).Error; err != nil {
			//return s.handleDBError("update avatar", err)
			return fmt.Errorf("update avatar:%w", customerrors.WrapError(err, "database_error", "Failed to update avatar"))
		}

		// Очистка кэша после обновления
		cacheKey := fmt.Sprintf("profile:%d", userID)
		s.cache.Delete(cacheKey)

		return nil
	})
}

// InitiatePasswordReset инициирует процесс сброса пароля с использованием транзакции
func (s *AuthService) InitiatePasswordReset(ctx context.Context, email string) error {
	user := models.User{
		Email: email,
	}
	if err := user.Validate(); err != nil {
		logger.Logger.Errorf("Invalid email format: %v", err)
		return fmt.Errorf("password reset failed: %w", err)
	}

	return s.dbRaw.WithTransactionRetry(ctx, func(tx *gorm.DB) error {
		var dbUser models.User
		if err := tx.First(&dbUser, "email = ?", email).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil // Тихо игнорируем, если пользователь не найден
			}
			//return s.handleDBError("find user for password reset", err)
			return fmt.Errorf("find user for password reset:%w", customerrors.WrapError(err, "database_error", "Failed to find user for password reset"))
		}

		token := uuid.New().String()
		expiresAt := time.Now().Add(1 * time.Hour)

		resetToken := &models.PasswordReset{
			UserID:    dbUser.ID,
			Token:     token,
			ExpiresAt: expiresAt,
			Used:      false,
		}

		if err := tx.Create(resetToken).Error; err != nil {
			//return s.handleDBError("create password reset token", err)
			return fmt.Errorf("create password reset token:%w", customerrors.WrapError(err, "database_error", "Failed to create password reset token"))
		}
		logger.Logger.Infof("Password reset initiated for user %s", email)
		return nil
	})
}

func (s *AuthService) ValidateResetToken(token string) error {
	var resetToken models.PasswordReset
	_, err := s.validateToken(&resetToken, token, "used = ?", false)
	if err != nil {
		return err
	}
	return nil
}

// ResetPassword сбрасывает пароль пользователя с использованием транзакции
func (s *AuthService) ResetPassword(ctx context.Context, token string, newPassword string) error {
	return s.dbRaw.WithTransactionRetry(ctx, func(tx *gorm.DB) error {
		var resetToken models.PasswordReset
		if err := tx.First(&resetToken, "token = ? AND used = false", token).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return customerrors.ErrInvalidToken
			}
			//return s.handleDBError("find reset token", err)
			return fmt.Errorf("find reset token:%w", customerrors.WrapError(err, "database_error", "Failed to find reset token"))
		}

		if time.Now().After(resetToken.ExpiresAt) {
			return customerrors.ErrInvalidToken
		}

		hashedPassword, err := s.hashPassword(newPassword)
		if err != nil {
			return err
		}

		if err := tx.Model(&models.User{}).Where("id = ?", resetToken.UserID).
			Update("password_hash", hashedPassword).Error; err != nil {
			//return s.handleDBError("update password", err)
			return fmt.Errorf("update password:%w", customerrors.WrapError(err, "database_error", "Failed to update password"))
		}

		resetToken.Used = true
		if err := tx.Save(&resetToken).Error; err != nil {
			//return s.handleDBError("mark token as used", err)
			return fmt.Errorf("mark token as used:%w", customerrors.WrapError(err, "database_error", "Failed to mark token as used"))
		}

		return nil
	})
}

// validateToken выполняет базовую проверку токена и возвращает срок действия и ошибку
func (s *AuthService) validateToken(table interface{}, token string, extraConditions ...interface{}) (time.Time, error) {
	query := s.db
	if len(extraConditions) > 0 {
		query = query.Where(extraConditions[0], extraConditions[1:]...)
	}
	if err := query.First(table, "token = ?", token).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return time.Time{}, customerrors.ErrInvalidToken
		}
		//return time.Time{}, s.handleDBError("validate token", err)
		return time.Time{}, fmt.Errorf("validate token:%w", customerrors.WrapError(err, "database_error", "Failed to validate token"))
	}

	// Предполагаем, что table имеет поле ExpiresAt
	switch t := table.(type) {
	case *models.RefreshToken:
		if time.Now().After(t.ExpiresAt) {
			return time.Time{}, customerrors.ErrInvalidToken
		}
		return t.ExpiresAt, nil
	case *models.PasswordReset:
		if time.Now().After(t.ExpiresAt) {
			return time.Time{}, customerrors.ErrInvalidToken
		}
		return t.ExpiresAt, nil
	default:
		return time.Time{}, fmt.Errorf("unsupported token type")
	}
}
