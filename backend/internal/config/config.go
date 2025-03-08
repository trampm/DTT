package config

import (
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"backend/pkg/logger"

	"github.com/go-playground/validator/v10"
	"github.com/joho/godotenv"
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

// envVar представляет переменную окружения с значением по умолчанию
type envVar struct {
	key      string
	required bool
	default_ string
}

// getEnv получает значение переменной окружения
func getEnv(ev envVar) string {
	val := os.Getenv(ev.key)
	if val == "" {
		if ev.required {
			logger.Logger.Warnf("Required environment variable %s is not set", ev.key)
		}
		return ev.default_
	}
	return val
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
	env := getEnv(envVar{key: "ENVIRONMENT", default_: "development"})
	if err := godotenv.Load(fmt.Sprintf(".env%s", getEnvFileSuffix(env))); err != nil {
		logger.Logger.Warnf("Error loading %s file: %v", fmt.Sprintf(".env%s", getEnvFileSuffix(env)), err)
	}

	environment := parseEnvironment(env)
	dbConfig := loadDatabaseConfig()
	corsConfig := loadCORSConfig()
	rateLimitConfig, err := loadRateLimitConfig()
	if err != nil {
		return nil, err
	}

	timezone := getEnv(envVar{key: "TIMEZONE", required: true, default_: "UTC"})
	if _, err := time.LoadLocation(timezone); err != nil {
		return nil, fmt.Errorf("invalid timezone %s: %w", timezone, err)
	}

	cfg := &Config{
		Environment:         environment,
		Database:            dbConfig,
		AppPort:             normalizePort(getEnv(envVar{key: "APP_PORT", required: true})),
		JWTSecretKey:        getEnv(envVar{key: "JWT_SECRET_KEY", required: true}),
		CSRFSecret:          getEnv(envVar{key: "CSRF_SECRET", required: true}),
		CORS:                corsConfig,
		RateLimit:           *rateLimitConfig,
		SwaggerHost:         getEnv(envVar{key: "SWAGGER_HOST", required: true}),
		LogLevel:            getEnv(envVar{key: "LOG_LEVEL", required: true, default_: "info"}),
		LogOutput:           getEnv(envVar{key: "LOG_OUTPUT", required: true, default_: "console"}),
		LogFilePath:         getEnv(envVar{key: "LOG_FILE_PATH", default_: "./logs/app.log"}),
		LogRotateMaxSize:    parseIntWithDefault(getEnv(envVar{key: "LOG_ROTATE_MAX_SIZE", default_: "10"}), 10),
		LogRotateMaxBackups: parseIntWithDefault(getEnv(envVar{key: "LOG_ROTATE_MAX_BACKUPS", default_: "3"}), 3),
		LogRotateMaxAge:     parseIntWithDefault(getEnv(envVar{key: "LOG_ROTATE_MAX_AGE", default_: "7"}), 7),
		LogRotateCompress:   parseBoolWithDefault(getEnv(envVar{key: "LOG_ROTATE_COMPRESS", default_: "true"}), true),
		Timezone:            timezone,
		LogFormat:           getEnv(envVar{key: "LOG_FORMAT", required: true, default_: "text"}),
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return cfg, nil
}

// loadDatabaseConfig загружает конфигурацию базы данных
func loadDatabaseConfig() DatabaseConfig {
	connMaxLifetime, _ := time.ParseDuration(getEnv(envVar{key: "DB_CONN_MAX_LIFETIME", default_: "5m"}))
	connTimeout, _ := time.ParseDuration(getEnv(envVar{key: "DB_CONN_TIMEOUT", default_: "10s"}))
	retryDelay, _ := time.ParseDuration(getEnv(envVar{key: "DB_RETRY_DELAY", default_: "1s"}))

	return DatabaseConfig{
		Host:                 getEnv(envVar{key: "DB_HOST", required: true}),
		Port:                 parseIntWithDefault(getEnv(envVar{key: "DB_PORT", required: true}), 5432),
		User:                 getEnv(envVar{key: "DB_USER", required: true}),
		Password:             getEnv(envVar{key: "DB_PASSWORD", required: true}),
		Name:                 getEnv(envVar{key: "DB_NAME", required: true}),
		SSLMode:              getEnv(envVar{key: "DB_SSL_MODE", default_: "disable"}),
		MaxOpenConns:         parseIntWithDefault(getEnv(envVar{key: "DB_MAX_OPEN_CONNS", default_: "25"}), 25),
		MaxIdleConns:         parseIntWithDefault(getEnv(envVar{key: "DB_MAX_IDLE_CONNS", default_: "10"}), 10),
		ConnMaxLifetime:      connMaxLifetime,
		ConnTimeout:          connTimeout,
		MaxRetries:           parseIntWithDefault(getEnv(envVar{key: "DB_MAX_RETRIES", default_: "3"}), 3),
		RetryDelay:           retryDelay,
		DeadlockLogLevel:     getEnv(envVar{key: "DB_DEADLOCK_LOG_LEVEL", default_: "error"}),
		TimeoutLogLevel:      getEnv(envVar{key: "DB_TIMEOUT_LOG_LEVEL", default_: "warn"}),
		RetryAttemptLogLevel: getEnv(envVar{key: "DB_RETRY_ATTEMPT_LOG_LEVEL", default_: "warn"}),
	}
}

// loadCORSConfig загружает конфигурацию CORS
func loadCORSConfig() CORSConfig {
	origins := strings.Split(getEnv(envVar{key: "CORS_ORIGINS", required: true}), ",")

	maxAgeStr := getEnv(envVar{key: "CORS_MAX_AGE", required: true})
	maxAge, err := time.ParseDuration(maxAgeStr)
	if err != nil {
		logger.Logger.Warnf("Invalid CORS_MAX_AGE format: %v, using default 1h", err)
		maxAge = 1 * time.Hour
	}

	allowCredentials := parseBoolWithDefault(getEnv(envVar{key: "CORS_ALLOW_CREDENTIALS", default_: "true"}), true)

	return CORSConfig{
		AllowOrigins:     origins,
		AllowCredentials: allowCredentials,
		MaxAge:           maxAge,
	}
}

// loadRateLimitConfig загружает конфигурацию Rate Limiting
func loadRateLimitConfig() (*RateLimitConfig, error) {
	periodStr := getEnv(envVar{key: "RATE_LIMIT_PERIOD", required: true})
	period, err := time.ParseDuration(periodStr)
	if err != nil {
		logger.Logger.Warnf("Invalid RATE_LIMIT_PERIOD format: %v, using default 10m", err)
		period = 10 * time.Minute
	}

	enabled := parseBoolWithDefault(getEnv(envVar{key: "RATE_LIMIT_ENABLED", default_: "false"}), false)
	requests := parseIntWithDefault(getEnv(envVar{key: "RATE_LIMIT_REQUESTS", required: true}), 500)

	return &RateLimitConfig{
		Period:   period,
		Requests: requests,
		Enabled:  enabled,
	}, nil
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

func getEnvFileSuffix(env string) string {
	if env == "development" {
		return ""
	}
	return "." + env
}

func normalizePort(port string) string {
	if port == "" {
		return ":8080"
	}
	if !strings.HasPrefix(port, ":") {
		return ":" + port
	}
	return port
}

func parseBoolWithDefault(s string, defaultVal bool) bool {
	if s == "" {
		return defaultVal
	}
	b, err := strconv.ParseBool(s)
	if err != nil {
		logger.Logger.Warnf("Failed to parse boolean: %s, using default value: %v", s, defaultVal)
		return defaultVal
	}
	return b
}

func parseIntWithDefault(s string, defaultVal int) int {
	if s == "" {
		return defaultVal
	}
	i, err := strconv.Atoi(s)
	if err != nil {
		logger.Logger.Warnf("Failed to parse integer: %s, using default value: %d", s, defaultVal)
		return defaultVal
	}
	return i
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
