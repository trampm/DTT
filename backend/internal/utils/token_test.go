package utils

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestGenerateToken(t *testing.T) {
	userID := uint(1)
	role := "admin"
	permissions := []string{"read", "write"}
	secretKey := "testsecretkey"

	token, err := GenerateToken(userID, role, permissions, secretKey)
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}
	if token == "" {
		t.Error("Expected non-empty token, got empty string")
	}

	// Проверяем, что токен можно разобрать
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})
	if err != nil || !parsedToken.Valid {
		t.Errorf("Generated token is invalid: %v", err)
	}
}

func TestValidateToken(t *testing.T) {
	userID := uint(1)
	role := "admin"
	permissions := []string{"read", "write"}
	secretKey := "testsecretkey"

	token, err := GenerateToken(userID, role, permissions, secretKey)
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	parsedUserID, parsedRole, parsedPermissions, err := ValidateToken(token, secretKey)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}
	if parsedUserID != userID || parsedRole != role || len(parsedPermissions) != len(permissions) {
		t.Errorf("ValidateToken returned incorrect values: got %d, %s, %v; want %d, %s, %v",
			parsedUserID, parsedRole, parsedPermissions, userID, role, permissions)
	}

	// Тест с истекшим токеном
	claims := Claims{
		UserID:      userID,
		Role:        role,
		Permissions: permissions,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-24 * time.Hour)),
		},
	}
	expiredToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	expiredTokenString, _ := expiredToken.SignedString([]byte(secretKey))
	_, _, _, err = ValidateToken(expiredTokenString, secretKey)
	if err == nil {
		t.Error("Expected error for expired token, got nil")
	}
}

func TestGenerateTokenForTest(t *testing.T) {
	userID := uint(1)
	role := "admin"
	permissions := []string{"read", "write"}
	secretKey := "testsecretkey"

	token, err := GenerateTokenForTest(userID, role, permissions, secretKey)
	if err != nil {
		t.Fatalf("GenerateTokenForTest failed: %v", err)
	}
	if token == "" {
		t.Error("Expected non-empty token, got empty string")
	}
}
