package errors

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "ErrUserExists",
			err:      ErrUserExists,
			expected: "user already exists",
		},
		{
			name:     "ErrUserNotFound",
			err:      ErrUserNotFound,
			expected: "user not found",
		},
		{
			name:     "ErrInvalidCredentials",
			err:      ErrInvalidCredentials,
			expected: "invalid credentials",
		},
		{
			name:     "ErrDatabaseConnection",
			err:      ErrDatabaseConnection,
			expected: "failed to connect to database",
		},
		{
			name:     "ErrTokenCreation",
			err:      ErrTokenCreation,
			expected: "failed to create token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrorsUniqueness(t *testing.T) {
	// Проверяем, что все ошибки уникальны
	errors := []error{
		ErrUserExists,
		ErrUserNotFound,
		ErrInvalidCredentials,
		ErrDatabaseConnection,
		ErrTokenCreation,
	}

	for i := 0; i < len(errors); i++ {
		for j := i + 1; j < len(errors); j++ {
			assert.NotEqual(t, errors[i], errors[j],
				"Errors should be unique: %v and %v", errors[i], errors[j])
		}
	}
}
