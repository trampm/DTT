package errors

import (
	"fmt"
)

type AppError struct {
	Code    string // Код ошибки (например, "database_error", "invalid_input")
	Message string // Человекочитаемое сообщение
	Err     error  // Исходная ошибка (можно nil)
}

func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func WrapError(err error, code string, message string) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
		Err:     err,
	}
}
