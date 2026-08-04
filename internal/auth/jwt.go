package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/termvault/termvault/internal/config"
)

type Claims struct {
	jwt.RegisteredClaims
	DeviceID string `json:"device_id"`
}

func GenerateTokenPair(userID uuid.UUID, deviceID string, cfg *config.Config) (accessToken string, refreshToken string, err error) {
	now := time.Now()
	accessClaims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(cfg.JWTExpiry)),
			ID:        uuid.New().String(),
		},
		DeviceID: deviceID,
	}
	accessToken, err = jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims).SignedString([]byte(cfg.JWTSecret))
	if err != nil {
		return
	}
	refreshClaims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(cfg.RefreshTokenExpiry)),
			ID:        uuid.New().String(),
		},
		DeviceID: deviceID,
	}
	refreshToken, err = jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).SignedString([]byte(cfg.JWTSecret))
	if err != nil {
		return
	}
	return
}

func VerifyAccessToken(tokenString string, cfg *config.Config) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(cfg.JWTSecret), nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}
	return nil, jwt.ErrTokenInvalidClaims
}