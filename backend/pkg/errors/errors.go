package errors

import (
	"errors"
)

// Определение пользовательских типов ошибок
var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserExists         = errors.New("user already exists")
	ErrUserNotFound       = errors.New("user not found")
	ErrTokenCreation      = errors.New("failed to create token")
	ErrDatabaseConnection = errors.New("failed to connect to database")
	ErrInvalidToken       = errors.New("invalid or expired token")
	ErrRoleNotFound       = errors.New("role not found")
	ErrPermissionNotFound = errors.New("permission not found")
	ErrInvalidRoleID      = errors.New("invalid role ID")
	// Добавьте другие пользовательские ошибки по необходимости
)
