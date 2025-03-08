package health

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockDB мок для базы данных
type MockDB struct {
	mock.Mock
}

func (m *MockDB) Ping() error {
	args := m.Called()
	return args.Error(0)
}

// Ensure MockDB implements PingableDB
var _ PingableDB = (*MockDB)(nil)

func TestHealthChecker_CheckHealth(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		setupMock  func(*MockDB)
		wantStatus int
		wantBody   map[string]interface{}
	}{
		{
			name: "Healthy",
			setupMock: func(db *MockDB) {
				db.On("Ping").Return(nil)
			},
			wantStatus: http.StatusOK,
			wantBody: map[string]interface{}{
				"status": "UP",
				"components": map[string]interface{}{
					"database": map[string]interface{}{
						"status":  "UP",
						"details": "Database connection is healthy",
					},
				},
			},
		},
		{
			name: "Unhealthy",
			setupMock: func(db *MockDB) {
				db.On("Ping").Return(assert.AnError)
			},
			wantStatus: http.StatusOK,
			wantBody: map[string]interface{}{
				"status": "DOWN",
				"components": map[string]interface{}{
					"database": map[string]interface{}{
						"status":  "DOWN",
						"details": "Database connection failed",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Создаем мок и настраиваем его
			mockDB := new(MockDB)
			tt.setupMock(mockDB)

			// Создаем HealthChecker
			checker := NewHealthChecker(mockDB)

			// Создаем тестовый контекст
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			// Выполняем проверку
			checker.CheckHealth(c)

			// Проверяем статус код
			assert.Equal(t, tt.wantStatus, w.Code)

			// Проверяем тело ответа
			var got map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &got)
			assert.NoError(t, err)

			// Удаляем timestamp из ответа, так как он динамический
			delete(got, "timestamp")

			assert.Equal(t, tt.wantBody, got)

			// Проверяем, что все ожидаемые вызовы были выполнены
			mockDB.AssertExpectations(t)
		})
	}
}

func TestHealthChecker_LivenessProbe(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Создаем мок
	mockDB := new(MockDB)

	// Создаем HealthChecker
	checker := NewHealthChecker(mockDB)

	// Создаем тестовый контекст
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	// Выполняем проверку
	checker.LivenessProbe(c)

	// Проверяем статус код
	assert.Equal(t, http.StatusOK, w.Code)

	// Проверяем тело ответа
	var got map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &got)
	assert.NoError(t, err)

	assert.Equal(t, map[string]interface{}{
		"status": "UP",
	}, got)
}

func TestHealthChecker_ReadinessProbe(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		setupMock  func(*MockDB)
		wantStatus int
		wantBody   map[string]interface{}
	}{
		{
			name: "Ready",
			setupMock: func(db *MockDB) {
				db.On("Ping").Return(nil)
			},
			wantStatus: http.StatusOK,
			wantBody: map[string]interface{}{
				"status": "UP",
			},
		},
		{
			name: "Not Ready",
			setupMock: func(db *MockDB) {
				db.On("Ping").Return(assert.AnError)
			},
			wantStatus: http.StatusServiceUnavailable,
			wantBody: map[string]interface{}{
				"status": "DOWN",
				"reason": "Database connection failed",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Создаем мок и настраиваем его
			mockDB := new(MockDB)
			tt.setupMock(mockDB)

			// Создаем HealthChecker
			checker := NewHealthChecker(mockDB)

			// Создаем тестовый контекст
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			// Выполняем проверку
			checker.ReadinessProbe(c)

			// Проверяем статус код
			assert.Equal(t, tt.wantStatus, w.Code)

			// Проверяем тело ответа
			var got map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &got)
			assert.NoError(t, err)

			assert.Equal(t, tt.wantBody, got)

			// Проверяем, что все ожидаемые вызовы были выполнены
			mockDB.AssertExpectations(t)
		})
	}
}
