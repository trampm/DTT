// internal/auth/models/base.go
package models

import (
	"time"
)

// BaseModel дублирует структуру gorm.Model для Swagger
type BaseModel struct {
	ID        uint       `json:"id" gorm:"primaryKey" swaggerignore:"true"`
	CreatedAt time.Time  `json:"created_at" swaggerignore:"true"`
	UpdatedAt time.Time  `json:"updated_at" swaggerignore:"true"`
	DeletedAt *time.Time `json:"deleted_at,omitempty" gorm:"index" swaggerignore:"true"`
}
