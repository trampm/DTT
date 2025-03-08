package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"backend/docs"
	"backend/internal/auth/handler"
	"backend/internal/auth/middleware"
	"backend/internal/auth/models"
	"backend/internal/auth/service"
	"backend/internal/config"
	"backend/internal/database"
	"backend/internal/utils"
	"backend/pkg/health"
	"backend/pkg/logger"
	"backend/pkg/metrics"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	csrf "github.com/utrack/gin-csrf"
)

// @title DTT API
// @version 1.0
// @description API сервер для DTT (Digital Task Tracker)
// @contact.name API Support
// @contact.email support@swagger.io
// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html
// @host localhost:8080
// @BasePath /
// @schemes http https
// @securityDefinitions.apikey Bearer
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.

// setupServer создает и настраивает HTTP сервер
func setupServer(handler http.Handler, port string) *http.Server {
	return &http.Server{
		Addr:         port,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

// setupRouter создает и настраивает роутер
func setupRouter(cfg *config.Config, authService service.AuthServiceInterface, healthChecker *health.HealthChecker) *gin.Engine {
	r := gin.New()

	r.Use(gin.Recovery())
	r.Use(middleware.ErrorHandler())
	r.Use(middleware.RequestLogger())
	r.Use(middleware.TraceMiddleware())
	r.Use(metrics.PrometheusMiddleware())
	r.Use(middleware.SecurityHeaders())
	r.Use(middleware.CORS(cfg))
	r.Use(middleware.RateLimiter(cfg.RateLimit.Requests, cfg.RateLimit.Period))

	docs.SwaggerInfo.Host = cfg.SwaggerHost
	docs.SwaggerInfo.BasePath = "/"
	docs.SwaggerInfo.Schemes = []string{"http", "https"}
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	r.GET("/csrf-token", func(c *gin.Context) {
		token := csrf.GetToken(c)
		c.JSON(200, gin.H{"csrf_token": token})
	})

	metricsGroup := r.Group("/metrics")
	{
		metricsGroup.GET("/", metrics.PrometheusHandler())
	}

	healthGroup := r.Group("/health")
	{
		healthGroup.GET("/", healthChecker.CheckHealth)
		healthGroup.GET("/live", healthChecker.LivenessProbe)
		healthGroup.GET("/ready", healthChecker.ReadinessProbe)
	}

	authHandler := handler.NewAuthHandler(authService, cfg)
	authGroup := r.Group("/auth")
	authGroup.Use(csrf.Middleware(csrf.Options{
		Secret: cfg.CSRFSecret,
	}))
	{
		authGroup.POST("/login", middleware.BindJSON[models.LoginRequest](), authHandler.Login)
		authGroup.POST("/register", middleware.BindJSON[models.RegisterRequest](), authHandler.Register)
		authGroup.POST("/refresh", middleware.BindJSON[models.RefreshRequest](), authHandler.Refresh)
		authGroup.POST("/logout", middleware.BindJSON[models.RefreshRequest](), authHandler.Logout)
		authGroup.POST("/roles", middleware.JWTMiddleware(cfg.JWTSecretKey, utils.ValidateToken), middleware.BindJSON[models.RoleRequest](), authHandler.CreateRole)
		authGroup.POST("/permissions", middleware.JWTMiddleware(cfg.JWTSecretKey, utils.ValidateToken), middleware.BindJSON[models.PermissionRequest](), authHandler.CreatePermission)
		authGroup.POST("/roles/assign", middleware.JWTMiddleware(cfg.JWTSecretKey, utils.ValidateToken), middleware.BindJSON[models.RoleAssignmentRequest](), authHandler.AssignRoleToUser)
		authGroup.POST("/permissions/assign", middleware.JWTMiddleware(cfg.JWTSecretKey, utils.ValidateToken), middleware.BindJSON[models.PermissionAssignmentRequest](), authHandler.AssignPermissionToRole)
		authGroup.POST("/password-reset", middleware.BindJSON[models.PasswordResetRequest](), authHandler.InitiatePasswordReset)
		authGroup.POST("/password-reset/confirm", middleware.BindJSON[models.PasswordResetConfirm](), authHandler.ResetPassword)
	}

	profileGroup := r.Group("/profile")
	profileGroup.Use(csrf.Middleware(csrf.Options{
		Secret: cfg.CSRFSecret,
	}))
	profileGroup.Use(middleware.JWTMiddleware(cfg.JWTSecretKey, utils.ValidateToken))
	{
		profileGroup.GET("/", authHandler.GetProfile)
		profileGroup.PUT("/", middleware.BindJSON[models.UpdateProfileRequest](), authHandler.UpdateProfile)
	}

	protectedGroup := r.Group("/protected")
	protectedGroup.Use(middleware.JWTMiddleware(cfg.JWTSecretKey, utils.ValidateToken))
	protectedGroup.Use(middleware.RBAC(authService, "read"))
	{
		protectedGroup.GET("/", func(c *gin.Context) {
			c.JSON(200, gin.H{"message": "Protected route with read permission"})
		})
	}

	return r
}

// initializeServices инициализирует сервисы приложения
func initializeServices(cfg *config.Config) (*database.DB, service.AuthServiceInterface, error) {
	db, err := database.ConnectDB(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	dsn := cfg.GetMigrationDSN()
	logger.Logger.Infof("Initializing AuthService with migration DSN: %s", dsn)
	authService := service.NewAuthService(db.Client, db, dsn) // db.Client как DB, db как TransactionRetrier
	if err := authService.InitializeDatabase(); err != nil {
		return nil, nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	return db, authService, nil
}

// run запускает приложение и возвращает ошибку, если что-то пошло не так
func run() error {
	// Загрузка конфигурации
	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Инициализация логгера с конфигурацией и ротацией
	if err := logger.InitLogger(
		cfg.LogLevel,
		cfg.LogOutput,
		cfg.LogFilePath,
		cfg.LogRotateMaxSize,
		cfg.LogRotateMaxBackups,
		cfg.LogRotateMaxAge,
		cfg.LogRotateCompress,
		cfg.Timezone,
		cfg.LogFormat,
	); err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}
	logger.Logger.Info(context.Background(), "Initializing application")
	logger.Logger.Info(context.Background(), fmt.Sprintf(
		"Logger initialized with level=%s, output=%s, maxSize=%dMB, maxBackups=%d, maxAge=%ddays, compress=%t, timezone=%s, format=%s",
		cfg.LogLevel, cfg.LogOutput, cfg.LogRotateMaxSize, cfg.LogRotateMaxBackups, cfg.LogRotateMaxAge, cfg.LogRotateCompress, cfg.Timezone, cfg.LogFormat,
	))

	// Настройка Gin в зависимости от окружения
	if cfg.Environment == config.Production {
		gin.SetMode(gin.ReleaseMode)
	}

	// Инициализация сервисов
	db, authService, err := initializeServices(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize services: %w", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			logger.Logger.Errorf("Failed to close database: %v", err)
		}
	}()

	// Запуск мониторинга пула соединений
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db.StartMonitoring(ctx, 5*time.Second) // Обновление метрик каждые 5 секунд

	// Инициализация health checker
	healthChecker := health.NewHealthChecker(db)

	// Настройка роутера и сервера
	router := setupRouter(cfg, authService, healthChecker)
	srv := setupServer(router, cfg.AppPort)

	// Запуск сервера в горутине
	go func() {
		logger.Logger.Infof("Starting server on port %s", cfg.AppPort)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Logger.Errorf("Failed to start server: %v", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Logger.Info(ctx, "Shutting down server...")

	var ctxShutdown context.Context
	ctxShutdown, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctxShutdown); err != nil {
		return fmt.Errorf("server forced to shutdown: %w", err)
	}

	logger.Logger.Info(ctx, "Server exited properly")
	return nil
}

func main() {
	if err := run(); err != nil {
		logger.Logger.Errorf("Application failed: %v", err)
		os.Exit(1)
	}
}
