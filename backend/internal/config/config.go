package config

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"backend/pkg/logger"

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
	Host                 string `validate:"required"`
	Port                 int    `validate:"required,min=1,max=65535"`
	User                 string `validate:"required"`
	Password             string `validate:"required"`
	Name                 string `validate:"required"`
	SSLMode              string
	MaxOpenConns         int           `validate:"gte=1"`
	MaxIdleConns         int           `validate:"gte=0"`
	ConnMaxLifetime      time.Duration `validate:"gt=0"`
	ConnTimeout          time.Duration `validate:"gt=0"`
	MaxRetries           int           `validate:"gte=1"`
	RetryDelay           time.Duration `validate:"gte=100ms,lt=5s"`
	DeadlockLogLevel     string        `validate:"required,oneof=debug info warn error"` // Уровень логирования дедлоков
	TimeoutLogLevel      string        `validate:"required,oneof=debug info warn error"` // Уровень логирования таймаутов
	RetryAttemptLogLevel string        `validate:"required,oneof=debug info warn error"` // Уровень логирования попыток
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
	Timezone            string `validate:"required"`
	LogFormat           string `validate:"required,oneof=text json"`
}

// LoadConfig загружает конфигурацию из переменных окружения
func LoadConfig() (*Config, error) {
	viper.SetConfigName(".env") // Имя файла конфигурации (без расширения)
	viper.SetConfigType("env")  // Тип файла конфигурации (json, toml, yaml, env)
	viper.AddConfigPath(".")    // Путь поиска файла конфигурации

	viper.AutomaticEnv() // Читать переменные окружения
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			logger.Logger.Warnf("No .env file found, using environment variables.")
		} else {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}

	environment := parseEnvironment(viper.GetString("ENVIRONMENT"))
	dbConfig := DatabaseConfig{
		Host:                 viper.GetString("DB_HOST"),
		Port:                 viper.GetInt("DB_PORT"),
		User:                 viper.GetString("DB_USER"),
		Password:             viper.GetString("DB_PASSWORD"),
		Name:                 viper.GetString("DB_NAME"),
		SSLMode:              viper.GetString("DB_SSL_MODE"),
		MaxOpenConns:         viper.GetInt("DB_MAX_OPEN_CONNS"),
		MaxIdleConns:         viper.GetInt("DB_MAX_IDLE_CONNS"),
		ConnMaxLifetime:      duration(viper.GetString("DB_CONN_MAX_LIFETIME")),
		ConnTimeout:          duration(viper.GetString("DB_CONN_TIMEOUT")),
		MaxRetries:           viper.GetInt("DB_MAX_RETRIES"),
		RetryDelay:           duration(viper.GetString("DB_RETRY_DELAY")),
		DeadlockLogLevel:     viper.GetString("DB_DEADLOCK_LOG_LEVEL"),
		TimeoutLogLevel:      viper.GetString("DB_TIMEOUT_LOG_LEVEL"),
		RetryAttemptLogLevel: viper.GetString("DB_RETRY_ATTEMPT_LOG_LEVEL"),
	}
	corsConfig := CORSConfig{
		AllowOrigins:     strings.Split(viper.GetString("CORS_ORIGINS"), ","),
		AllowCredentials: viper.GetBool("CORS_ALLOW_CREDENTIALS"),
		MaxAge:           duration(viper.GetString("CORS_MAX_AGE")),
	}

	rateLimitConfig := RateLimitConfig{
		Requests: viper.GetInt("RATE_LIMIT_REQUESTS"),
		Period:   duration(viper.GetString("RATE_LIMIT_PERIOD")),
		Enabled:  viper.GetBool("RATE_LIMIT_ENABLED"),
	}

	timezone := viper.GetString("TIMEZONE")
	if _, err := time.LoadLocation(timezone); err != nil {
		return nil, fmt.Errorf("invalid timezone %s: %w", timezone, err)
	}

	cfg := &Config{
		Environment:         environment,
		Database:            dbConfig,
		AppPort:             normalizePort(viper.GetString("APP_PORT")),
		JWTSecretKey:        viper.GetString("JWT_SECRET_KEY"),
		CSRFSecret:          viper.GetString("CSRF_SECRET"),
		CORS:                corsConfig,
		RateLimit:           rateLimitConfig,
		SwaggerHost:         viper.GetString("SWAGGER_HOST"),
		LogLevel:            viper.GetString("LOG_LEVEL"),
		LogOutput:           viper.GetString("LOG_OUTPUT"),
		LogFilePath:         viper.GetString("LOG_FILE_PATH"),
		LogRotateMaxSize:    viper.GetInt("LOG_ROTATE_MAX_SIZE"),
		LogRotateMaxBackups: viper.GetInt("LOG_ROTATE_MAX_BACKUPS"),
		LogRotateMaxAge:     viper.GetInt("LOG_ROTATE_MAX_AGE"),
		LogRotateCompress:   viper.GetBool("LOG_ROTATE_COMPRESS"),
		Timezone:            timezone,
		LogFormat:           viper.GetString("LOG_FORMAT"),
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return cfg, nil
}

func duration(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0
	}
	return d
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
