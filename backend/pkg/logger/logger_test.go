package logger

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLogger(t *testing.T) {
	oldLogger := Logger
	defer func() { Logger = oldLogger }()

	Logger = NewLogger(Options{
		Level:     LevelDebug,
		AddSource: true,
		Output:    &bytes.Buffer{},
	})

	ctx := context.Background()

	tests := []struct {
		name     string
		logFunc  func()
		wantText string
	}{
		{
			name: "Info",
			logFunc: func() {
				Logger.Info(ctx, "test info")
			},
			wantText: "test info",
		},
		{
			name: "Debug",
			logFunc: func() {
				Logger.Debug(ctx, "test debug")
			},
			wantText: "test debug",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.logFunc()
		})
	}
}

func TestLoggerWithContext(t *testing.T) {
	oldLogger := Logger
	defer func() { Logger = oldLogger }()

	buf := &bytes.Buffer{}
	Logger = NewLogger(Options{
		Level:     LevelDebug,
		AddSource: true,
		Output:    buf,
	})

	// Создаем контекст с тестовыми данными
	ctx := context.WithValue(context.Background(), RequestIDKey, "test-id")

	// Логируем сообщение с контекстом
	Logger.Info(ctx, "test with context")

	// Проверяем, что лог содержит все необходимые поля
	output := buf.String()
	assert.Contains(t, output, "level=INFO")
	assert.Contains(t, output, "test with context")
	assert.Contains(t, output, "request_id=test-id")
}

func TestLoggerLevels(t *testing.T) {
	oldLogger := Logger
	defer func() { Logger = oldLogger }()

	buf := &bytes.Buffer{}
	Logger = NewLogger(Options{
		Level:     LevelDebug,
		AddSource: true,
		Output:    buf,
	})

	ctx := context.Background()

	// Debug сообщение
	Logger.Debug(ctx, "test debug")
	assert.Contains(t, buf.String(), "test debug")

	// Info сообщение
	buf.Reset()
	Logger.Info(ctx, "test info")
	assert.Contains(t, buf.String(), "test info")

	// Warn сообщение
	buf.Reset()
	Logger.Warn(ctx, "test warn")
	assert.Contains(t, buf.String(), "test warn")

	// Error сообщение
	buf.Reset()
	Logger.Error(ctx, "test error", assert.AnError)
	assert.Contains(t, buf.String(), "test error")
}
