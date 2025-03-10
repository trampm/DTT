package models

import (
	"errors"
	"regexp"
	"strings"
	"time"
)

// User представляет пользователя системы
type User struct {
	BaseModel
	Email        string   `json:"email" gorm:"uniqueIndex;not null"`
	PasswordHash string   `json:"-" gorm:"not null"`
	RoleID       *uint    `json:"role_id" gorm:"column:role_id"`
	Role         *Role    `json:"role,omitempty" gorm:"foreignKey:RoleID"`
	Profile      *Profile `json:"profile,omitempty" gorm:"foreignKey:UserID"`
}

// Validate проверяет корректность данных пользователя
func (u *User) Validate() error {
	return u.ValidateEmail()
}

// ValidateEmail проверяет формат email
func (u *User) ValidateEmail() error {
	email := strings.TrimSpace(u.Email)
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(email) {
		return errors.New("invalid email format")
	}
	return nil
}

// Role представляет роль пользователя
// swagger:model Role
type Role struct {
	BaseModel
	Name         string `gorm:"uniqueIndex;not null" json:"name"`
	Description  string `json:"description"`
	ParentID     *uint  `json:"parent_id,omitempty"`
	Parent       *Role  `gorm:"foreignKey:ParentID" json:"parent,omitempty"`
	ParentRoleID *uint
}

// Permission представляет разрешение в системе
type Permission struct {
	BaseModel
	Name        string `gorm:"uniqueIndex;not null"`
	Description string
}

// RolePermission связывает роли и разрешения
type RolePermission struct {
	BaseModel
	RoleID       uint `gorm:"uniqueIndex:idx_role_permission"`
	PermissionID uint `gorm:"uniqueIndex:idx_role_permission"`
}

// RefreshToken представляет refresh-токен для обновления сессии
type RefreshToken struct {
	BaseModel
	UserID    uint      `gorm:"index"`
	Token     string    `gorm:"uniqueIndex"`
	ExpiresAt time.Time `gorm:"index"`
	IPAddress string    // Add this
	UserAgent string    // Add this
}

// RefreshRequest структура для запроса обновления токена
type RefreshRequest struct {
	// Refresh токен
	// required: true
	// example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// Profile представляет профиль пользователя
type Profile struct {
	BaseModel
	UserID      uint `gorm:"uniqueIndex;not null"`
	FirstName   string
	LastName    string
	Avatar      string
	PhoneNumber string
	Bio         string
}

// UpdateProfileRequest структура для обновления профиля
type UpdateProfileRequest struct {
	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name"`
	PhoneNumber string `json:"phone_number"`
	Bio         string `json:"bio"`
}

// ProfileResponse структура для ответа с данными профиля
type ProfileResponse struct {
	ID          uint   `json:"id"`
	Email       string `json:"email"`
	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name"`
	PhoneNumber string `json:"phone_number"`
	Bio         string `json:"bio"`
	Avatar      string `json:"avatar"`
	Role        string `json:"role"`
}

// PasswordResetRequest структура для запроса сброса пароля
type PasswordResetRequest struct {
	// Email пользователя
	// required: true
	// example: user@example.com
	Email string `json:"email" binding:"required,email"`
}

// PasswordResetConfirm структура для подтверждения сброса пароля
type PasswordResetConfirm struct {
	// Токен сброса пароля
	// required: true
	// example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
	Token string `json:"token" binding:"required"`

	// Новый пароль
	// required: true
	// example: newpassword123
	NewPassword string `json:"new_password" binding:"required,min=6"`
}

// PasswordReset представляет запись о сбросе пароля
type PasswordReset struct {
	BaseModel
	UserID    uint      `gorm:"not null"`
	Token     string    `gorm:"uniqueIndex;not null"`
	ExpiresAt time.Time `gorm:"not null"`
	Used      bool      `gorm:"default:false"`
}
