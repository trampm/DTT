package utils

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	UserID      uint     `json:"user_id"`
	Role        string   `json:"role"`        // Название роли
	Permissions []string `json:"permissions"` // Список прав
	jwt.RegisteredClaims
}

// GenerateToken создает новый JWT токен
func GenerateToken(userID uint, role string, permissions []string, secretKey string, accessTokenLifetime time.Duration) (string, error) {
	claims := Claims{
		UserID:      userID,
		Role:        role,
		Permissions: permissions,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(accessTokenLifetime)), // Use the passed-in duration
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secretKey))
}

// ValidateToken проверяет JWT токен и возвращает ID пользователя, роль и права
func ValidateToken(tokenString, secretKey string) (uint, string, []string, error) {
	fmt.Printf("ValidateToken called. Token string: %s\n", tokenString)

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})
	if err != nil {
		fmt.Printf("ValidateToken: Error parsing token: %v\n", err) // ADD THIS
		return 0, "", nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		fmt.Printf("ValidateToken: Invalid claims or token\n") // ADD THIS
		return 0, "", nil, jwt.ErrSignatureInvalid
	}

	fmt.Printf("ValidateToken: UserID=%d, Role=%s, Permissions=%v\n", claims.UserID, claims.Role, claims.Permissions) // ADD THIS

	return claims.UserID, claims.Role, claims.Permissions, nil
}

// GenerateTokenForTest создает тестовый токен и возвращает ошибку, если генерация не удалась
func GenerateTokenForTest(userID uint, role string, permissions []string, secretKey string, accessTokenLifetime time.Duration) (string, error) {
	token, err := GenerateToken(userID, role, permissions, secretKey, accessTokenLifetime)
	if err != nil {
		return "", fmt.Errorf("failed to generate test token: %w", err)
	}
	return token, nil
}
