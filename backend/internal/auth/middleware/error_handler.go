// internal/auth/middleware/error_handler.go
package middleware

import (
	"fmt"
	"net/http"

	"backend/pkg/errors" // Import our error package

	"github.com/gin-gonic/gin"
)

func ErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				// Handle panic
				fmt.Println("Panic recovered:", r) // Log panic
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"status":  "error",
					"message": "Internal server error",
				})
			}
		}()

		c.Next()

		// Check for errors after processing
		err := c.Errors.Last() // Get the last error
		if err != nil {

			if appErr, ok := err.Err.(*errors.AppError); ok { // Use err.Err (unwrapped)
				// Handle AppError
				switch appErr.Code {
				case "invalid_input":
					c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
						"status":  "error",
						"message": appErr.Message,
					})
				case "unauthorized":
					c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
						"status":  "error",
						"message": appErr.Message,
					})

				case "not_found":
					c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
						"status":  "error",
						"message": appErr.Message,
					})
				case "database_error":
					//TODO: Здесь бы хорошо отправлять в мониторинг, что у нас проблемы с базой
					c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
						"status":  "error",
						"message": "Database error", // Don't expose internal DB details!
					})
				default:
					// Unknown error
					c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
						"status":  "error",
						"message": "Internal server error",
					})
				}
			} else {
				// Handle other errors
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"status":  "error",
					"message": "Internal server error",
				})
			}
			c.Abort() // Stop further handlers
		}
	}
}
