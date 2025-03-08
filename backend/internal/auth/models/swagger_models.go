package models

// RoleRequest представляет запрос на создание роли
type RoleRequest struct {
	// Название роли
	// required: true
	// example: moderator
	Name string `json:"name" binding:"required" example:"moderator"`

	// Описание роли
	// example: Moderator with limited access
	Description string `json:"description" example:"Moderator with limited access"`
}

// PermissionRequest представляет запрос на создание права
type PermissionRequest struct {
	// Название права
	// required: true
	// example: delete
	Name string `json:"name" binding:"required" example:"delete"`

	// Описание права
	// example: Delete resources
	Description string `json:"description" example:"Delete resources"`
}

// RoleAssignmentRequest представляет запрос на назначение роли пользователю
type RoleAssignmentRequest struct {
	// ID пользователя
	// required: true
	// example: 1
	UserID uint `json:"user_id" binding:"required" example:"1"`

	// ID роли
	// required: true
	// example: 2
	RoleID uint `json:"role_id" binding:"required" example:"2"`
}

// PermissionAssignmentRequest представляет запрос на назначение права роли
type PermissionAssignmentRequest struct {
	// ID роли
	// required: true
	// example: 2
	RoleID uint `json:"role_id" binding:"required" example:"2"`

	// ID права
	// required: true
	// example: 1
	PermissionID uint `json:"permission_id" binding:"required" example:"1"`
}

type RegisterRequest struct {
	Email    string `json:"email" binding:"required,email" example:"user@example.com"`
	Password string `json:"password" binding:"required,min=8" example:"password123"`
	Name     string `json:"name" binding:"required" example:"John Doe"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email" example:"user@example.com"`
	Password string `json:"password" binding:"required,min=8" example:"password123"`
}

type AuthResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Token   string `json:"token,omitempty"`
}

type ErrorResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// SuccessRole структура для успешного ответа при создании роли
type SuccessRole struct {
	Message string `json:"message"`
	Role    Role   `json:"role"`
}

type SuccessPermission struct {
	Message    string `json:"message"`
	Permission string `json:"permission"`
}
