package config

import (
	"fmt"
	"log"
	"reflect"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
)

// Environment представляет окружение приложения
type Environment int

const (
	Development Environment = iota
	Production
	Testing
)

func (e *Environment) UnmarshalText(text []byte) error {
	switch string(text) {
	case "development":
		*e = Development
	case "production":
		*e = Production
	case "testing":
		*e = Testing
	default:
		return fmt.Errorf("invalid environment: %s", text)
	}
	return nil
}

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
	AllowOrigins     []string      `validate:"required,min=1"`
	AllowCredentials bool          `validate:"-"`
	MaxAge           time.Duration `validate:"min=0"`
}

// RateLimitConfig содержит настройки для rate limiting
type RateLimitConfig struct {
	Requests int           `validate:"min=1"`
	Period   time.Duration `validate:"min=1s"`
	Enabled  bool          `validate:"-"`
}

// DatabaseConfig содержит настройки базы данных
type DatabaseConfig struct {
	Host                 string        `mapstructure:"DB_HOST" validate:"required"`
	Port                 int           `mapstructure:"DB_PORT" validate:"required,min=1,max=65535"`
	User                 string        `mapstructure:"DB_USER" validate:"required"`
	Password             string        `mapstructure:"DB_PASSWORD" validate:"required"`
	Name                 string        `mapstructure:"DB_NAME" validate:"required"`
	SSLMode              string        `mapstructure:"DB_SSL_MODE" validate:"required,oneof=disable require verify-full"`
	MaxOpenConns         int           `mapstructure:"DB_MAX_OPEN_CONNS" validate:"min=1"`
	MaxIdleConns         int           `mapstructure:"DB_MAX_IDLE_CONNS" validate:"min=0"`
	ConnMaxLifetime      time.Duration `mapstructure:"DB_CONN_MAX_LIFETIME" validate:"min=1s"`
	ConnTimeout          time.Duration `mapstructure:"DB_CONN_TIMEOUT" validate:"min=1s"`
	MaxRetries           int           `mapstructure:"DB_MAX_RETRIES" validate:"min=0"`
	RetryDelay           time.Duration `mapstructure:"DB_RETRY_DELAY" validate:"min=1s"`
	DeadlockLogLevel     string        `mapstructure:"DB_DEADLOCK_LOG_LEVEL" validate:"oneof=debug info warn error"`
	TimeoutLogLevel      string        `mapstructure:"DB_TIMEOUT_LOG_LEVEL" validate:"oneof=debug info warn error"`
	RetryAttemptLogLevel string        `mapstructure:"DB_RETRY_ATTEMPT_LOG_LEVEL" validate:"oneof=debug info warn error"`
	MonitoringInterval   time.Duration `mapstructure:"DB_MONITORING_INTERVAL" validate:"min=1s"`
}

// Config содержит все настройки приложения
type Config struct {
	Environment         Environment    `validate:"required"`
	Database            DatabaseConfig `validate:"required"`
	AppPort             string         `validate:"required,startswith=:"`
	JWTSecretKey        string         `validate:"required,min=64"`
	CSRFSecret          string         `validate:"required,min=32"`
	CORS                CORSConfig
	RateLimit           RateLimitConfig
	SwaggerHost         string
	LogLevel            string `validate:"required,oneof=debug info warn error"`
	LogOutput           string `validate:"required,oneof=console file"`
	LogFormat           string `validate:"required,oneof=text json"`
	LogFilePath         string `validate:"required_if_file"`
	LogRotateMaxSize    int    `validate:"gte=1"`
	LogRotateMaxBackups int    `validate:"gte=0"`
	LogRotateMaxAge     int    `validate:"gte=0"`
	LogRotateCompress   bool
	Timezone            string        `validate:"required"`
	AccessTokenLifetime time.Duration `validate:"required,min=1s"`
}

// LoadConfig загружает конфигурацию из переменных окружения
func LoadConfig() (*Config, error) {
	log.Println("Loading configuration...")

	v := viper.New()
	v.SetConfigFile(".env")
	v.AutomaticEnv()
	log.Println("Setting default values...")
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
	v.SetDefault("DB_MONITORING_INTERVAL", "5s")
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
	log.Println("Default values set")

	log.Println("Reading configuration file...")
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			log.Printf("Failed to read config file: %v\n", err)
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		log.Println("No config file found, using environment variables")
	}

	log.Println("Config data before unmarshal:")
	for key, value := range v.AllSettings() {
		log.Printf("%s: %v\n", key, value)
	}

	var cfg Config
	log.Println("Unmarshalling configuration...")
	if err := v.Unmarshal(&cfg, viper.DecodeHook(
		mapstructure.ComposeDecodeHookFunc(
			decodeEnvironmentHook, // Ваш кастомный хук
			mapstructure.StringToTimeDurationHookFunc(),
			mapstructure.StringToSliceHookFunc(","),
		),
	)); err != nil {
		log.Printf("Failed to unmarshal config: %v\n", err)
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	log.Println("Config after unmarshal:")
	log.Printf("%+v\n", cfg)

	log.Println("Validating configuration...")
	if err := cfg.validate(); err != nil {
		log.Printf("Validation failed: %v\n", err)
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	log.Println("Configuration loaded and validated successfully")
	return &cfg, nil
}

// decodeEnvironmentHook преобразует строку в Environment
func decodeEnvironmentHook(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
	log.Printf("Decoding environment: f=%v, t=%v, data=%v\n", f, t, data)
	if f.Kind() != reflect.String {
		return data, nil
	}
	if t != reflect.TypeOf(Environment(0)) {
		return data, nil
	}

	var env Environment
	err := env.UnmarshalText([]byte(data.(string)))
	if err != nil {
		log.Printf("Failed to decode environment: %v\n", err)
		return nil, err
	}
	log.Printf("Decoded environment: %v\n", env)
	return env, nil
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

	// Кастомная проверка для LogFilePath
	validate.RegisterValidation("required_if_file", func(fl validator.FieldLevel) bool {
		logOutput := fl.Parent().FieldByName("LogOutput").String()
		if logOutput == "file" {
			return fl.Field().String() != ""
		}
		return true
	})

	log.Println("Validating config struct...")
	if err := validate.Struct(c); err != nil {
		log.Printf("Validation errors: %v\n", err)
		return err
	}
	return nil
}
