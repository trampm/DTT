package utils

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	UserID      uint                `json:"user_id"`
	Role        string              `json:"role"`
	Permissions map[string]struct{} `json:"permissions"`
	jwt.RegisteredClaims
}

// GenerateToken создает новый JWT токен
func GenerateToken(userID uint, role string, permissions map[string]struct{}, secretKey string, accessTokenLifetime time.Duration) (string, error) {
	claims := Claims{
		UserID:      userID,
		Role:        role,
		Permissions: permissions,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(accessTokenLifetime)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString([]byte(secretKey))
}

// ValidateToken проверяет JWT токен и возвращает ID пользователя, роль и права
func ValidateToken(tokenString, secretKey string) (uint, string, map[string]struct{}, error) {
	fmt.Printf("ValidateToken called. Token string: %s\n", tokenString)

	// Первая попытка проверки с текущим секретом
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Проверяем алгоритм подписи перед возвратом ключа
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok || token.Method.Alg() != "HS512" {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secretKey), nil
	})

	// Если ошибка связана с подписью, пробуем предыдущий секрет
	if err != nil && errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		prevSecret := os.Getenv("PREV_JWT_SECRET_KEY")
		if prevSecret == "" {
			return 0, "", nil, fmt.Errorf("invalid token signature")
		}

		token, err = jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok || token.Method.Alg() != "HS512" {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(prevSecret), nil
		})
	}

	// Обработка ошибок после всех попыток проверки
	if err != nil {
		fmt.Printf("ValidateToken error: %v\n", err)
		return 0, "", nil, err
	}

	// Проверка валидности токена и claims
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		fmt.Printf("ValidateToken: Invalid claims or token\n")
		return 0, "", nil, jwt.ErrTokenInvalidClaims
	}

	fmt.Printf("ValidateToken: UserID=%d, Role=%s, Permissions=%v\n", claims.UserID, claims.Role, claims.Permissions)
	return claims.UserID, claims.Role, claims.Permissions, nil
}

// GenerateTokenForTest создает тестовый токен и возвращает ошибку, если генерация не удалась
func GenerateTokenForTest(userID uint, role string, permissions map[string]struct{}, secretKey string, accessTokenLifetime time.Duration) (string, error) {
	token, err := GenerateToken(userID, role, permissions, secretKey, accessTokenLifetime)
	if err != nil {
		return "", fmt.Errorf("failed to generate test token: %w", err)
	}
	return token, nil
}
