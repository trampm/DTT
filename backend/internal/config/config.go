package config

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/spf13/viper"
)

// Environment представляет окружение приложения
type Environment int

const (
	Development Environment = iota
	Production
	Testing
)

// String возвращает строковое представление Environment
func (e Environment) String() string {
	switch e {
	case Development:
		return "development"
	case Production:
		return "production"
	case Testing:
		return "testing"
	default:
		panic("unknown environment")
	}
}

// CORSConfig содержит настройки CORS
type CORSConfig struct {
	AllowOrigins     []string
	AllowCredentials bool
	MaxAge           time.Duration
}

// RateLimitConfig содержит настройки для rate limiting
type RateLimitConfig struct {
	Requests int
	Period   time.Duration
	Enabled  bool
}

// DatabaseConfig содержит настройки базы данных
type DatabaseConfig struct {
	Host                 string        `mapstructure:"DB_HOST"`
	Port                 int           `mapstructure:"DB_PORT"`
	User                 string        `mapstructure:"DB_USER"`
	Password             string        `mapstructure:"DB_PASSWORD"`
	Name                 string        `mapstructure:"DB_NAME"`
	SSLMode              string        `mapstructure:"DB_SSL_MODE"`
	MaxOpenConns         int           `mapstructure:"DB_MAX_OPEN_CONNS"`
	MaxIdleConns         int           `mapstructure:"DB_MAX_IDLE_CONNS"`
	ConnMaxLifetime      time.Duration `mapstructure:"DB_CONN_MAX_LIFETIME"`
	ConnTimeout          time.Duration `mapstructure:"DB_CONN_TIMEOUT"`
	MaxRetries           int           `mapstructure:"DB_MAX_RETRIES"`
	RetryDelay           time.Duration `mapstructure:"DB_RETRY_DELAY"`
	DeadlockLogLevel     string        `mapstructure:"DB_DEADLOCK_LOG_LEVEL"`
	TimeoutLogLevel      string        `mapstructure:"DB_TIMEOUT_LOG_LEVEL"`
	RetryAttemptLogLevel string        `mapstructure:"DB_RETRY_ATTEMPT_LOG_LEVEL"`
	MonitoringInterval   time.Duration `mapstructure:"DB_MONITORING_INTERVAL"`
}

// Config содержит все настройки приложения
type Config struct {
	Environment         Environment    `validate:"required"`
	Database            DatabaseConfig `validate:"required"`
	AppPort             string         `validate:"required,startswith=:"`
	JWTSecretKey        string         `validate:"required"`
	CSRFSecret          string         `validate:"required,gte=32"`
	CORS                CORSConfig
	RateLimit           RateLimitConfig
	SwaggerHost         string
	LogLevel            string `validate:"required,oneof=debug info warn error"`
	LogOutput           string `validate:"required,oneof=console file"`
	LogFilePath         string `validate:"required_if=LogOutput file"`
	LogRotateMaxSize    int    `validate:"gte=1"`
	LogRotateMaxBackups int    `validate:"gte=0"`
	LogRotateMaxAge     int    `validate:"gte=0"`
	LogRotateCompress   bool
	Timezone            string        `validate:"required"`
	LogFormat           string        `validate:"required,oneof=text json"`
	AccessTokenLifetime time.Duration `validate:"required"`
}

// LoadConfig загружает конфигурацию из переменных окружения
func LoadConfig() (*Config, error) {
	v := viper.New()
	v.SetConfigFile(".env")
	v.AutomaticEnv()

	// Установка значений по умолчанию
	v.SetDefault("ENVIRONMENT", "development")
	v.SetDefault("APP_PORT", ":8080")
	v.SetDefault("JWT_SECRET_KEY", "secret")
	v.SetDefault("CSRF_SECRET", "csrfsecret")
	v.SetDefault("SWAGGER_HOST", "localhost:8080")
	v.SetDefault("DB_HOST", "localhost")
	v.SetDefault("DB_PORT", 5432)
	v.SetDefault("DB_USER", "postgres")
	v.SetDefault("DB_PASSWORD", "postgres")
	v.SetDefault("DB_NAME", "dtt")
	v.SetDefault("DB_SSL_MODE", "disable")
	v.SetDefault("DB_MAX_OPEN_CONNS", 25)
	v.SetDefault("DB_MAX_IDLE_CONNS", 10)
	v.SetDefault("DB_CONN_MAX_LIFETIME", "5m")
	v.SetDefault("DB_CONN_TIMEOUT", "10s")
	v.SetDefault("DB_MAX_RETRIES", 3)
	v.SetDefault("DB_RETRY_DELAY", "1s")
	v.SetDefault("DB_MONITORING_INTERVAL", "5s") // Значение по умолчанию 5 секунд
	v.SetDefault("CORS_ORIGINS", "http://localhost:3000")
	v.SetDefault("CORS_MAX_AGE", "1h")
	v.SetDefault("CORS_ALLOW_CREDENTIALS", true)
	v.SetDefault("RATE_LIMIT_ENABLED", false)
	v.SetDefault("RATE_LIMIT_REQUESTS", 500)
	v.SetDefault("RATE_LIMIT_PERIOD", "10m")
	v.SetDefault("LOG_LEVEL", "debug")
	v.SetDefault("LOG_OUTPUT", "console")
	v.SetDefault("LOG_FILE_PATH", "./logs/app.log")
	v.SetDefault("LOG_ROTATE_MAX_SIZE", 10)
	v.SetDefault("LOG_ROTATE_MAX_BACKUPS", 3)
	v.SetDefault("LOG_ROTATE_MAX_AGE", 7)
	v.SetDefault("LOG_ROTATE_COMPRESS", true)
	v.SetDefault("TIMEZONE", "UTC")
	v.SetDefault("LOG_FORMAT", "text")
	v.SetDefault("DB_DEADLOCK_LOG_LEVEL", "error")
	v.SetDefault("DB_TIMEOUT_LOG_LEVEL", "warn")
	v.SetDefault("DB_RETRY_ATTEMPT_LOG_LEVEL", "info")
	v.SetDefault("ACCESS_TOKEN_LIFETIME", "30m")

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &cfg, nil
}

// GetDSN возвращает строку подключения к базе данных для GORM
func (c *Config) GetDSN() string {
	sslMode := c.Database.SSLMode
	if sslMode == "" {
		sslMode = "disable"
	}

	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s timezone=%s",
		c.Database.Host, c.Database.Port, c.Database.User,
		c.Database.Password, c.Database.Name, sslMode, c.Timezone)
}

// GetMigrationDSN возвращает строку подключения в формате URL для миграций
func (c *Config) GetMigrationDSN() string {
	sslMode := c.Database.SSLMode
	if sslMode == "" {
		sslMode = "disable"
	}

	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s&timezone=%s",
		c.Database.User, c.Database.Password, c.Database.Host,
		c.Database.Port, c.Database.Name, sslMode, c.Timezone)
}

// Вспомогательные функции

func normalizePort(port string) string {
	if port == "" {
		return ":8080"
	}
	if !strings.HasPrefix(port, ":") {
		return ":" + port
	}
	return port
}

func parseEnvironment(env string) Environment {
	switch strings.ToLower(env) {
	case "production":
		return Production
	case "testing":
		return Testing
	default:
		return Development
	}
}

// validate проверяет корректность конфигурации
func (c *Config) validate() error {
	validate := validator.New()

	// Регистрируем кастомный валидатор для Environment
	validate.RegisterCustomTypeFunc(func(field reflect.Value) interface{} {
		if value, ok := field.Interface().(Environment); ok {
			return value.String()
		}
		return nil
	}, Environment(0))

	if err := validate.Struct(c); err != nil {
		return err
	}
	return nil
}
