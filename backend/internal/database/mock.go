package database

import (
	"backend/pkg/health"

	"github.com/stretchr/testify/mock"
	"gorm.io/gorm"
)

// MockDB мок для базы данных
type MockDB struct {
	mock.Mock
}

// Ensure MockDB implements GormDB and PingableDB
var _ GormDB = (*MockDB)(nil)
var _ health.PingableDB = (*MockDB)(nil) // Уточняем пространство имен

// NewMockDB создает новый мок базы данных
func NewMockDB() *MockDB {
	return &MockDB{}
}

// Ping реализует PingableDB
func (m *MockDB) Ping() error {
	args := m.Called()
	return args.Error(0)
}

// AutoMigrate реализует GormDB
func (m *MockDB) AutoMigrate(dst ...interface{}) error {
	args := m.Called(dst...)
	return args.Error(0)
}

// Create реализует GormDB
func (m *MockDB) Create(value interface{}) *gorm.DB {
	args := m.Called(value)
	if db, ok := args.Get(0).(*gorm.DB); ok {
		return db
	}
	return &gorm.DB{Error: args.Error(0)}
}

// First реализует GormDB
func (m *MockDB) First(dst interface{}, conds ...interface{}) *gorm.DB {
	args := m.Called(append([]interface{}{dst}, conds...)...)
	if db, ok := args.Get(0).(*gorm.DB); ok {
		return db
	}
	return &gorm.DB{Error: args.Error(0)}
}

// Exec реализует GormDB
func (m *MockDB) Exec(sql string, vars ...interface{}) *gorm.DB {
	args := m.Called(append([]interface{}{sql}, vars...)...)
	if db, ok := args.Get(0).(*gorm.DB); ok {
		return db
	}
	return &gorm.DB{Error: args.Error(0)}
}

// Save реализует GormDB
func (m *MockDB) Save(value interface{}) *gorm.DB {
	args := m.Called(value)
	if db, ok := args.Get(0).(*gorm.DB); ok {
		return db
	}
	return &gorm.DB{Error: args.Error(0)}
}

// Preload реализует GormDB
func (m *MockDB) Preload(query string, args ...interface{}) *gorm.DB {
	argsCalled := m.Called(append([]interface{}{query}, args...)...)
	if db, ok := argsCalled.Get(0).(*gorm.DB); ok {
		return db
	}
	return &gorm.DB{Error: argsCalled.Error(0)}
}

// Find реализует GormDB
func (m *MockDB) Find(dest interface{}, conds ...interface{}) *gorm.DB {
	args := m.Called(append([]interface{}{dest}, conds...)...)
	if db, ok := args.Get(0).(*gorm.DB); ok {
		return db
	}
	return &gorm.DB{Error: args.Error(0)}
}

// Delete реализует GormDB
func (m *MockDB) Delete(value interface{}, conds ...interface{}) *gorm.DB {
	args := m.Called(append([]interface{}{value}, conds...)...)
	if db, ok := args.Get(0).(*gorm.DB); ok {
		return db
	}
	return &gorm.DB{Error: args.Error(0)}
}

// FirstOrCreate реализует GormDB
func (m *MockDB) FirstOrCreate(dst interface{}, conds ...interface{}) *gorm.DB {
	args := m.Called(append([]interface{}{dst}, conds...)...)
	if db, ok := args.Get(0).(*gorm.DB); ok {
		return db
	}
	return &gorm.DB{Error: args.Error(0)}
}

// Model реализует GormDB
func (m *MockDB) Model(value interface{}) *gorm.DB {
	args := m.Called(value)
	if db, ok := args.Get(0).(*gorm.DB); ok {
		return db
	}
	return &gorm.DB{Error: args.Error(0)}
}

// Where реализует GormDB
func (m *MockDB) Where(query interface{}, args ...interface{}) *gorm.DB {
	argsCalled := m.Called(append([]interface{}{query}, args...)...)
	if db, ok := argsCalled.Get(0).(*gorm.DB); ok {
		return db
	}
	return &gorm.DB{Error: argsCalled.Error(0)}
}
