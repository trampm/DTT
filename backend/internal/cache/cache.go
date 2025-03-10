package cache

import (
	"sync"
	"time"

	"backend/internal/database"
	"backend/pkg/logger"
)

// Role структура для хранения роли в кэше
type Role struct {
	ID          int
	Name        string
	Description string
	UpdatedAt   time.Time
}

// Permission структура для хранения права в кэше
type Permission struct {
	ID          int
	Name        string
	Description string
	UpdatedAt   time.Time
}

// Cache структура для хранения кэша ролей и прав
type Cache struct {
	Roles       sync.Map // map[int]Role
	Permissions sync.Map // map[int]Permission
	db          *database.DB
}

// NewCache создает новый экземпляр кэша
func NewCache(db *database.DB) *Cache {
	return &Cache{
		Roles:       sync.Map{},
		Permissions: sync.Map{},
		db:          db,
	}
}

// GetRole получает роль из кэша или базы данных
func (c *Cache) GetRole(roleID int) (Role, error) {
	if cached, ok := c.Roles.Load(roleID); ok {
		return cached.(Role), nil
	}

	var role Role
	err := c.db.Client.Model(&role).Where("id = ?", roleID).First(&role).Error
	if err != nil {
		return Role{}, err
	}

	c.Roles.Store(roleID, role)
	logger.Logger.Debugf("Cached role ID=%d, Name=%s", role.ID, role.Name)
	return role, nil
}

// GetPermission получает право из кэша или базы данных
func (c *Cache) GetPermission(permID int) (Permission, error) {
	if cached, ok := c.Permissions.Load(permID); ok {
		return cached.(Permission), nil
	}

	var perm Permission
	err := c.db.Client.Model(&perm).Where("id = ?", permID).First(&perm).Error
	if err != nil {
		return Permission{}, err
	}

	c.Permissions.Store(permID, perm)
	logger.Logger.Debugf("Cached permission ID=%d, Name=%s", perm.ID, perm.Name)
	return perm, nil
}

// InvalidateRole удаляет роль из кэша
func (c *Cache) InvalidateRole(roleID int) {
	c.Roles.Delete(roleID)
	logger.Logger.Debugf("Invalidated role cache for ID=%d", roleID)
}

// InvalidatePermission удаляет право из кэша
func (c *Cache) InvalidatePermission(permID int) {
	c.Permissions.Delete(permID)
	logger.Logger.Debugf("Invalidated permission cache for ID=%d", permID)
}
