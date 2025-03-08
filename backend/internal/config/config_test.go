package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name         string
		envVars      map[string]string
		expectedPort string
		expectedEnv  Environment
		expectedCORS CORSConfig
		expectError  bool
	}{
		{
			name: "Неверный формат RATE_LIMIT_PERIOD",
			envVars: map[string]string{
				"ENVIRONMENT":       "development",
				"APP_PORT":          ":8080",
				"RATE_LIMIT_PERIOD": "invalid",
				"DB_HOST":           "localhost",
				"DB_PORT":           "5432",
				"DB_USER":           "postgres",
				"DB_PASSWORD":       "postgres",
				"DB_NAME":           "dtt",
				"JWT_SECRET_KEY":    "secret",
				"RATE_LIMIT_REQ":    "100",
			},
			expectedPort: ":8080",
			expectedEnv:  Development,
			expectedCORS: CORSConfig{
				AllowOrigins:     []string{"http://localhost:3000"},
				AllowCredentials: true,
				MaxAge:           time.Hour,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Очищаем все переменные окружения перед тестом
			for _, key := range []string{
				"ENVIRONMENT", "APP_PORT", "RATE_LIMIT_PERIOD",
				"DB_HOST", "DB_PORT", "DB_USER", "DB_PASSWORD",
				"DB_NAME", "JWT_SECRET_KEY", "RATE_LIMIT_REQ",
			} {
				os.Unsetenv(key)
			}

			// Устанавливаем тестовые переменные окружения
			for k, v := range tt.envVars {
				os.Setenv(k, v)
			}

			// Восстанавливаем переменные окружения после теста
			defer func() {
				for k := range tt.envVars {
					os.Unsetenv(k)
				}
			}()

			_, err := LoadConfig()
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestEnvironmentString(t *testing.T) {
	tests := []struct {
		name        string
		env         Environment
		expected    string
		shouldPanic bool
	}{
		{
			name:     "Development",
			env:      Development,
			expected: "development",
		},
		{
			name:     "Production",
			env:      Production,
			expected: "production",
		},
		{
			name:     "Testing",
			env:      Testing,
			expected: "testing",
		},
		{
			name:        "Неизвестное окружение",
			env:         Environment(999),
			shouldPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.shouldPanic {
				assert.Panics(t, func() {
					_ = tt.env.String()
				})
			} else {
				assert.Equal(t, tt.expected, tt.env.String())
			}
		})
	}
}

func TestGetDSN(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		expected string
	}{
		{
			name: "Development DSN",
			config: Config{
				Environment: Development,
				Database: DatabaseConfig{
					Host:     "localhost",
					Port:     5432,
					User:     "postgres",
					Password: "password",
					Name:     "dtt",
				},
			},
			expected: "host=localhost port=5432 user=postgres password=password dbname=dtt sslmode=disable",
		},
		{
			name: "Production DSN",
			config: Config{
				Environment: Production,
				Database: DatabaseConfig{
					Host:     "db.production.com",
					Port:     5432,
					User:     "app",
					Password: "secret",
					Name:     "dtt_prod",
				},
			},
			expected: "host=db.production.com port=5432 user=app password=secret dbname=dtt_prod sslmode=require",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dsn := tt.config.GetDSN()
			assert.Equal(t, tt.expected, dsn)
		})
	}
}
