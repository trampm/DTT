package handler

import (
	"fmt"
	"net/http"
	"strings"

	"backend/internal/auth/middleware"
	"backend/internal/auth/models"
	"backend/internal/auth/service"
	"backend/internal/config"
	"backend/internal/utils"
	customerrors "backend/pkg/errors"

	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	Service service.AuthServiceInterface
	Config  *config.Config
}

func NewAuthHandler(service service.AuthServiceInterface, cfg *config.Config) *AuthHandler {
	return &AuthHandler{
		Service: service,
		Config:  cfg,
	}
}

// generateTokens генерирует access и refresh токены для пользователя
func (h *AuthHandler) generateTokens(c *gin.Context, userID uint, roleName string, permissions map[string]struct{}) (string, string, error) {
	accessToken, err := utils.GenerateToken(userID, roleName, permissions, h.Config.JWTSecretKey, h.Config.AccessTokenLifetime)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate access token: %w", err)
	}

	// Get the client's IP address and User-Agent
	ipAddress := h.getClientIP(c)      // Use a method to safely extract the IP
	userAgent := c.Request.UserAgent() // Get the User-Agent from the request

	refreshToken, err := h.Service.GenerateRefreshToken(c.Request.Context(), userID, ipAddress, userAgent)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}
	return accessToken, refreshToken, nil
}

func (h *AuthHandler) getClientIP(c *gin.Context) string {
	ip := c.GetHeader("X-Forwarded-For")
	if ip == "" {
		ip = c.Request.RemoteAddr
	}

	parts := strings.Split(ip, ":")
	if len(parts) > 0 {
		ip = parts[0]
	}
	return ip
}

// Register регистрирует нового пользователя
// @Summary Регистрация пользователя
// @Description Регистрирует нового пользователя в системе
// @Tags auth
// @Accept json
// @Produce json
// @Param user body models.RegisterRequest true "Данные пользователя"
// @Success 201 {object} map[string]string "Успешная регистрация"
// @Failure 400 {object} models.ErrorResponse "Неверный ввод"
// @Failure 409 {object} models.ErrorResponse "Пользователь уже существует"
// @Router /auth/register [post]
func (h *AuthHandler) Register(c *gin.Context) {
	req, ok := middleware.GetRequest[models.RegisterRequest](c)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid input"})
		return
	}

	if err := h.Service.RegisterUser(c.Request.Context(), req.Email, req.Password); err != nil {
		if err == customerrors.ErrUserExists {
			c.JSON(http.StatusConflict, gin.H{"error": "user already exists"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to register user: %v", err)})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "user registered successfully"})
}

// Login аутентифицирует пользователя
// @Summary Аутентификация пользователя
// @Description Аутентифицирует пользователя и возвращает access и refresh токены
// @Tags auth
// @Accept json
// @Produce json
// @Param credentials body models.LoginRequest true "Учетные данные"
// @Success 200 {object} map[string]string "Успешный логин с токенами"
// @Failure 400 {object} models.ErrorResponse "Неверный ввод"
// @Failure 401 {object} models.ErrorResponse "Неверные учетные данные"
// @Failure 500 {object} models.ErrorResponse "Внутренняя ошибка сервера"
// @Router /auth/login [post]
func (h *AuthHandler) Login(c *gin.Context) {
	req, ok := middleware.GetRequest[models.LoginRequest](c)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid input"})
		return
	}

	user, err := h.Service.AuthenticateUser(req.Email, req.Password)
	if err == customerrors.ErrInvalidCredentials || err == customerrors.ErrUserNotFound {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to authenticate user: %v", err)})
		return
	}
	if user == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unexpected nil user"})
		return
	}

	userWithRole, err := h.Service.GetUserWithRole(req.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to fetch user role: %v", err)})
		return
	}
	if userWithRole == nil || userWithRole.RoleID == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unexpected nil user or role"})
		return
	}

	permissions, err := h.Service.GetRolePermissionsRecursive(*userWithRole.RoleID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to fetch permissions: %v", err)})
		return
	}

	accessToken, refreshToken, err := h.generateTokens(c, user.ID, userWithRole.Role.Name, permissions)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
	})
}

// Refresh обновляет access-токен с помощью refresh-токена
// @Summary Обновление токена
// @Description Обновляет access-токен используя refresh-токен
// @Tags auth
// @Accept json
// @Produce json
// @Param refresh body models.RefreshRequest true "Refresh токен"
// @Success 200 {object} map[string]string "Успешное обновление токена"
// @Failure 400 {object} models.ErrorResponse "Неверный ввод"
// @Failure 401 {object} models.ErrorResponse "Неверный или истекший refresh-токен"
// @Failure 500 {object} models.ErrorResponse "Внутренняя ошибка сервера"
// @Router /auth/refresh [post]
// @Security Bearer
func (h *AuthHandler) Refresh(c *gin.Context) {
	req, ok := middleware.GetRequest[models.RefreshRequest](c)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid input"})
		return
	}

	userID, err := h.Service.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired refresh token"})
		return
	}

	userWithRole, err := h.Service.GetUserWithRoleByID(userID)
	if err != nil || userWithRole == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch user"})
		return
	}
	if userWithRole.RoleID == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "user role not assigned"})
		return
	}

	permissions, err := h.Service.GetRolePermissionsRecursive(*userWithRole.RoleID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to fetch permissions: %v", err)})
		return
	}

	accessToken, refreshToken, err := h.generateTokens(c, userWithRole.ID, userWithRole.Role.Name, permissions)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
	})
}

// CreateRole создает новую роль
// @Summary Создание роли
// @Description Создает новую роль в системе
// @Tags auth
// @Accept json
// @Produce json
// @Param role body models.RoleRequest true "Данные роли"
// @Success 201 {object} models.SuccessRole "Успешное создание роли"
// @Failure 400 {object} models.ErrorResponse "Неверный ввод"
// @Failure 409 {object} models.ErrorResponse "Роль уже существует"
// @Failure 500 {object} models.ErrorResponse "Внутренняя ошибка сервера"
// @Router /auth/roles [post]
// @Security Bearer
func (h *AuthHandler) CreateRole(c *gin.Context) {
	req, ok := middleware.GetRequest[models.RoleRequest](c)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid input"})
		return
	}

	// Передаём контекст из запроса
	role, err := h.Service.CreateRole(c.Request.Context(), req.Name, req.Description)
	if err == customerrors.ErrUserExists {
		c.JSON(http.StatusConflict, gin.H{"error": "role already exists"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to create role: %v", err)})
		return
	}

	c.JSON(http.StatusCreated, role)
}

// CreatePermission создает новое право
// @Summary Создание права
// @Description Создает новое право в системе
// @Tags auth
// @Accept json
// @Produce json
// @Param permission body models.PermissionRequest true "Данные права"
// @Success 201 {object} models.SuccessPermission "Успешное создание права"
// @Failure 400 {object} models.ErrorResponse "Неверный ввод"
// @Failure 409 {object} models.ErrorResponse "Право уже существует"
// @Failure 500 {object} models.ErrorResponse "Внутренняя ошибка сервера"
// @Router /auth/permissions [post]
// @Security Bearer
func (h *AuthHandler) CreatePermission(c *gin.Context) {
	req, ok := middleware.GetRequest[models.PermissionRequest](c)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid input"})
		return
	}

	// Передаём контекст из запроса
	permission, err := h.Service.CreatePermission(c.Request.Context(), req.Name, req.Description)
	if err == customerrors.ErrUserExists {
		c.JSON(http.StatusConflict, gin.H{"error": "permission already exists"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to create permission: %v", err)})
		return
	}

	c.JSON(http.StatusCreated, permission)
}

// AssignRoleToUser назначает роль пользователю
// @Summary Назначение роли пользователю
// @Description Назначает указанную роль пользователю
// @Tags auth
// @Accept json
// @Produce json
// @Param assignment body models.RoleAssignmentRequest true "Данные назначения"
// @Success 200 {object} map[string]string "Успешное назначение роли"
// @Failure 400 {object} models.ErrorResponse "Неверный ввод"
// @Failure 404 {object} models.ErrorResponse "Пользователь или роль не найдены"
// @Failure 500 {object} models.ErrorResponse "Внутренняя ошибка сервера"
// @Router /auth/roles/assign [post]
// @Security Bearer
func (h *AuthHandler) AssignRoleToUser(c *gin.Context) {
	req, ok := middleware.GetRequest[models.RoleAssignmentRequest](c)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid input"})
		return
	}

	// Передаём контекст из запроса
	err := h.Service.AssignRoleToUser(c.Request.Context(), req.UserID, req.RoleID)
	if err == customerrors.ErrUserNotFound {
		c.JSON(http.StatusNotFound, gin.H{"error": "user or role not found"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to assign role: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "role assigned successfully"})
}

// AssignPermissionToRole назначает право роли
// @Summary Назначение права роли
// @Description Назначает указанное право роли
// @Tags auth
// @Accept json
// @Produce json
// @Param assignment body models.PermissionAssignmentRequest true "Данные назначения"
// @Success 200 {object} map[string]string "Успешное назначение права"
// @Failure 400 {object} models.ErrorResponse "Неверный ввод"
// @Failure 404 {object} models.ErrorResponse "Роль или право не найдены"
// @Failure 500 {object} models.ErrorResponse "Внутренняя ошибка сервера"
// @Router /auth/permissions/assign [post]
// @Security Bearer
func (h *AuthHandler) AssignPermissionToRole(c *gin.Context) {
	req, ok := middleware.GetRequest[models.PermissionAssignmentRequest](c)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid input"})
		return
	}

	// Передаём контекст из запроса
	err := h.Service.AssignPermissionToRole(c.Request.Context(), req.RoleID, req.PermissionID)
	if err == customerrors.ErrUserNotFound {
		c.JSON(http.StatusNotFound, gin.H{"error": "role or permission not found"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to assign permission: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "permission assigned successfully"})
}

// Logout отзывает refresh-токен пользователя
// @Summary Выход из системы
// @Description Отзывает refresh-токен, завершая сессию пользователя
// @Tags auth
// @Accept json
// @Produce json
// @Param refresh body models.RefreshRequest true "Refresh токен"
// @Success 200 {object} map[string]string "Успешный выход"
// @Failure 400 {object} models.ErrorResponse "Неверный ввод"
// @Failure 401 {object} models.ErrorResponse "Неверный refresh-токен"
// @Failure 500 {object} models.ErrorResponse "Внутренняя ошибка сервера"
// @Router /auth/logout [post]
// @Security Bearer
func (h *AuthHandler) Logout(c *gin.Context) {
	req, ok := middleware.GetRequest[models.RefreshRequest](c)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid input"})
		return
	}

	err := h.Service.RevokeRefreshToken(c.Request.Context(), req.RefreshToken)
	if err == customerrors.ErrInvalidToken {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid refresh token"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to revoke refresh token: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "successfully logged out"})
}

// GetProfile получает профиль пользователя
// @Summary Получение профиля
// @Description Получает профиль текущего пользователя
// @Tags profile
// @Produce json
// @Security Bearer
// @Success 200 {object} models.ProfileResponse "Успешное получение профиля"
// @Failure 401 {object} models.ErrorResponse "Неавторизован"
// @Failure 500 {object} models.ErrorResponse "Внутренняя ошибка сервера"
// @Router /profile [get]
func (h *AuthHandler) GetProfile(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)                                    // Используем helper из middleware
	fmt.Printf("AuthHandler.GetProfile: userID=%d, exists=%v\n", userID, exists) // ADD THIS
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	profile, err := h.Service.GetProfile(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to get profile: %v", err)})
		return
	}

	c.JSON(http.StatusOK, profile)
}

// UpdateProfile обновляет профиль пользователя
// @Summary Обновление профиля
// @Description Обновляет профиль текущего пользователя
// @Tags profile
// @Accept json
// @Produce json
// @Security Bearer
// @Param profile body models.UpdateProfileRequest true "Данные профиля"
// @Success 200 {object} models.ProfileResponse "Успешное обновление профиля"
// @Failure 400 {object} models.ErrorResponse "Неверный ввод"
// @Failure 401 {object} models.ErrorResponse "Неавторизован"
// @Failure 500 {object} models.ErrorResponse "Внутренняя ошибка сервера"
// @Router /profile [put]
func (h *AuthHandler) UpdateProfile(c *gin.Context) {
	userID := c.GetUint("user_id")
	if userID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	req, ok := middleware.GetRequest[models.UpdateProfileRequest](c)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid input"})
		return
	}

	if err := h.Service.UpdateProfile(c.Request.Context(), userID, &req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to update profile: %v", err)})
		return
	}

	profile, err := h.Service.GetProfile(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to get updated profile: %v", err)})
		return
	}

	c.JSON(http.StatusOK, profile)
}

// InitiatePasswordReset инициирует процесс сброса пароля
// @Summary Инициация сброса пароля
// @Description Отправляет токен для сброса пароля на email пользователя
// @Tags auth
// @Accept json
// @Produce json
// @Param request body models.PasswordResetRequest true "Email пользователя"
// @Success 200 {object} map[string]string "Успешная инициация сброса"
// @Failure 400 {object} models.ErrorResponse "Неверный ввод"
// @Failure 500 {object} models.ErrorResponse "Внутренняя ошибка сервера"
// @Router /auth/password-reset [post]
func (h *AuthHandler) InitiatePasswordReset(c *gin.Context) {
	req, ok := middleware.GetRequest[models.PasswordResetRequest](c)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid input"})
		return
	}

	if err := h.Service.InitiatePasswordReset(c.Request.Context(), req.Email); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to initiate password reset: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "if the email exists, a password reset link will be sent"})
}

// ResetPassword сбрасывает пароль пользователя
// @Summary Сброс пароля
// @Description Устанавливает новый пароль с использованием токена сброса
// @Tags auth
// @Accept json
// @Produce json
// @Param request body models.PasswordResetConfirm true "Токен и новый пароль"
// @Success 200 {object} map[string]string "Успешный сброс пароля"
// @Failure 400 {object} models.ErrorResponse "Неверный ввод"
// @Failure 401 {object} models.ErrorResponse "Неверный или истекший токен"
// @Failure 500 {object} models.ErrorResponse "Внутренняя ошибка сервера"
// @Router /auth/password-reset/confirm [post]
func (h *AuthHandler) ResetPassword(c *gin.Context) {
	req, ok := middleware.GetRequest[models.PasswordResetConfirm](c)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid input"})
		return
	}

	if err := h.Service.ResetPassword(c.Request.Context(), req.Token, req.NewPassword); err != nil {
		if err == customerrors.ErrInvalidToken {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to reset password: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "password has been reset successfully"})
}

// BatchCreateRoles обрабатывает запрос на пакетное создание ролей
// @Summary Пакетное создание ролей
// @Description Создает несколько ролей в системе пакетно
// @Tags auth
// @Accept json
// @Produce json
// @Param roles body []models.RoleRequest true "Массив данных ролей"
// @Success 201 {object} map[string][]models.Role "Успешное создание ролей"
// @Failure 400 {object} models.ErrorResponse "Неверный ввод"
// @Failure 500 {object} models.ErrorResponse "Внутренняя ошибка сервера"
// @Router /auth/roles/batch [post]
// @Security Bearer
func (h *AuthHandler) BatchCreateRoles(c *gin.Context) {
	var req []models.RoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid input: " + err.Error()})
		return
	}

	rolesData := make([]struct {
		Name        string
		Description string
	}, len(req))
	for i, r := range req {
		rolesData[i] = struct {
			Name        string
			Description string
		}{Name: r.Name, Description: r.Description}
	}

	roles, err := h.Service.BatchCreateRoles(c.Request.Context(), rolesData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to batch create roles: %v", err)})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"roles": roles})
}

// BatchCreatePermissions обрабатывает запрос на пакетное создание прав
// @Summary Пакетное создание прав
// @Description Создает несколько прав в системе пакетно
// @Tags auth
// @Accept json
// @Produce json
// @Param permissions body []models.PermissionRequest true "Массив данных прав"
// @Success 201 {object} map[string][]models.Permission "Успешное создание прав"
// @Failure 400 {object} models.ErrorResponse "Неверный ввод"
// @Failure 500 {object} models.ErrorResponse "Внутренняя ошибка сервера"
// @Router /auth/permissions/batch [post]
// @Security Bearer
func (h *AuthHandler) BatchCreatePermissions(c *gin.Context) {
	var req []models.PermissionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid input: " + err.Error()})
		return
	}

	permissionsData := make([]struct {
		Name        string
		Description string
	}, len(req))
	for i, p := range req {
		permissionsData[i] = struct {
			Name        string
			Description string
		}{Name: p.Name, Description: p.Description}
	}

	permissions, err := h.Service.BatchCreatePermissions(c.Request.Context(), permissionsData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to batch create permissions: %v", err)})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"permissions": permissions})
}
