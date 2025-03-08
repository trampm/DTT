package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

type ctxKey string

const (
	TraceIDKey   ctxKey = "trace_id" // Обновляем имя ключа для консистентности
	RequestIDKey ctxKey = "request_id"
)

// LogLevel представляет уровень логирования
type LogLevel int

const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelWarn
	LevelError
)

// Logger представляет собой глобальный логгер приложения
var Logger *AppLogger

// AppLogger - обертка над slog.Logger с дополнительными методами
type AppLogger struct {
	slog *slog.Logger
	opts Options
}

// Options содержит настройки логгера
type Options struct {
	Level     LogLevel
	AddSource bool
	Output    io.Writer
	Timezone  *time.Location
	Format    string
}

// DefaultOptions возвращает настройки по умолчанию
func DefaultOptions() Options {
	return Options{
		Level:     LevelDebug,
		AddSource: true,
		Output:    os.Stdout,
		Timezone:  time.UTC,
		Format:    "text",
	}
}

// InitLogger инициализирует глобальный логгер с заданными параметрами
func InitLogger(level string, output string, filePath string, maxSize int, maxBackups int, maxAge int, compress bool, timezone string, format string) error {
	var logLevel LogLevel
	switch level {
	case "debug":
		logLevel = LevelDebug
	case "info":
		logLevel = LevelInfo
	case "warn":
		logLevel = LevelWarn
	case "error":
		logLevel = LevelError
	default:
		logLevel = LevelInfo
	}

	var logOutput io.Writer
	switch output {
	case "console":
		logOutput = os.Stdout
	case "file":
		if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
			return fmt.Errorf("failed to create log directory: %w", err)
		}
		logOutput = &lumberjack.Logger{
			Filename:   filePath,
			MaxSize:    maxSize,
			MaxBackups: maxBackups,
			MaxAge:     maxAge,
			Compress:   compress,
		}
	default:
		logOutput = os.Stdout
	}

	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return fmt.Errorf("failed to load timezone %s: %w", timezone, err)
	}

	opts := Options{
		Level:     logLevel,
		AddSource: true,
		Output:    logOutput,
		Timezone:  loc,
		Format:    format,
	}
	Logger = NewLogger(opts)
	return nil
}

// NewLogger создает новый логгер с указанными настройками
func NewLogger(opts Options) *AppLogger {
	handler := newHandler(opts)
	return &AppLogger{
		slog: slog.New(handler),
		opts: opts,
	}
}

// newHandler создает новый обработчик логов с поддержкой формата и часового пояса
func newHandler(opts Options) slog.Handler {
	level := convertLevel(opts.Level)
	handlerOpts := &slog.HandlerOptions{
		AddSource: opts.AddSource,
		Level:     level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{
					Key:   a.Key,
					Value: slog.TimeValue(a.Value.Time().In(opts.Timezone)),
				}
			}
			return a
		},
	}

	if opts.Format == "json" {
		return slog.NewJSONHandler(opts.Output, handlerOpts)
	}
	return slog.NewTextHandler(opts.Output, handlerOpts)
}

// convertLevel конвертирует LogLevel в slog.Level
func convertLevel(level LogLevel) slog.Level {
	switch level {
	case LevelInfo:
		return slog.LevelInfo
	case LevelWarn:
		return slog.LevelWarn
	case LevelError:
		return slog.LevelError
	default:
		return slog.LevelDebug
	}
}

// SetLevel устанавливает новый уровень логирования
func (l *AppLogger) SetLevel(level LogLevel) {
	l.opts.Level = level
	l.slog = slog.New(newHandler(l.opts))
}

// WithContext создает новый логгер с контекстом
func (l *AppLogger) WithContext(ctx context.Context) *AppLogger {
	if ctx == nil {
		return l
	}

	fields := make([]interface{}, 0)

	if traceID := GetTraceID(ctx); traceID != "" {
		fields = append(fields, "trace_id", traceID)
	}

	if requestID, ok := ctx.Value(RequestIDKey).(string); ok && requestID != "" {
		fields = append(fields, "request_id", requestID)
	}

	if len(fields) == 0 {
		return l
	}

	return &AppLogger{
		slog: l.slog.With(fields...),
		opts: l.opts,
	}
}

// GetTraceID возвращает ID трассировки из контекста
func GetTraceID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if traceID, ok := ctx.Value(TraceIDKey).(string); ok {
		return traceID
	}
	return ""
}

// log логирует сообщение с указанным уровнем и атрибутами
func (l *AppLogger) log(ctx context.Context, level slog.Level, msg string, attrs ...any) {
	if ctx != nil {
		// Автоматически добавляем trace_id из контекста, если он есть
		if traceID := GetTraceID(ctx); traceID != "" {
			attrs = append(attrs, "trace_id", traceID)
		}
		// Добавляем request_id, если он есть
		if requestID, ok := ctx.Value(RequestIDKey).(string); ok && requestID != "" {
			attrs = append(attrs, "request_id", requestID)
		}
	}
	l.slog.Log(ctx, level, msg, attrs...)
}

// logf логирует форматированное сообщение с указанным уровнем
func (l *AppLogger) logf(level slog.Level, format string, args ...interface{}) {
	l.log(context.TODO(), level, fmt.Sprintf(format, args...))
}

// Debug логирует отладочное сообщение
func (l *AppLogger) Debug(ctx context.Context, msg string, attrs ...any) {
	l.log(ctx, slog.LevelDebug, msg, attrs...)
}

// Debugf логирует форматированное отладочное сообщение
func (l *AppLogger) Debugf(format string, args ...interface{}) {
	l.logf(slog.LevelDebug, format, args...)
}

// Info логирует информационное сообщение
func (l *AppLogger) Info(ctx context.Context, msg string, attrs ...any) {
	l.log(ctx, slog.LevelInfo, msg, attrs...)
}

// Infof логирует форматированное информационное сообщение
func (l *AppLogger) Infof(format string, args ...interface{}) {
	l.logf(slog.LevelInfo, format, args...)
}

// Warn логирует предупреждение
func (l *AppLogger) Warn(ctx context.Context, msg string, attrs ...any) {
	l.log(ctx, slog.LevelWarn, msg, attrs...)
}

// Warnf логирует форматированное предупреждение
func (l *AppLogger) Warnf(format string, args ...interface{}) {
	l.logf(slog.LevelWarn, format, args...)
}

// Error логирует ошибку
func (l *AppLogger) Error(ctx context.Context, msg string, err error, attrs ...any) {
	if err != nil {
		attrs = append(attrs, "error", err, "stack", fmt.Sprintf("%+v", err))
	}
	l.log(ctx, slog.LevelError, msg, attrs...)
}

// Errorf логирует форматированное сообщение об ошибке
func (l *AppLogger) Errorf(format string, args ...interface{}) {
	l.logf(slog.LevelError, format, args...)
}

// Методы без контекста для обратной совместимости
func (l *AppLogger) InfoNoCtx(msg string, attrs ...any) {
	l.log(context.Background(), slog.LevelInfo, msg, attrs...)
}

func (l *AppLogger) ErrorNoCtx(msg string, err error, attrs ...any) {
	if err != nil {
		attrs = append(attrs, "error", err)
	}
	l.log(context.Background(), slog.LevelError, msg, attrs...)
}

// NewTestLogger создает новый логгер для тестов
func NewTestLogger(w io.Writer) *AppLogger {
	return NewLogger(Options{
		Level:     LevelDebug,
		AddSource: true,
		Output:    w,
		Timezone:  time.UTC,
		Format:    "text",
	})
}
