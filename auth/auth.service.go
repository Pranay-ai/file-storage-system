package auth

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/Pranay-ai/file-storage-system/database"

	"github.com/golang-jwt/jwt/v4"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Claims defines the structure of the JWT payload, holding the user ID
// and standard expiration/issuance times.
type Claims struct {
	UserID primitive.ObjectID `json:"user_id"`
	jwt.RegisteredClaims
}

// AuthService handles all authentication logic, including JWT creation,
// validation, and management of the token blacklist via Redis.
type AuthService struct {
	jwtSecret    []byte
	redisService *database.RedisService
}

// NewAuthService creates and returns a new instance of AuthService.
// It retrieves the JWT secret from environment variables and accepts the
// Redis service as a dependency.
func NewAuthService(redisService *database.RedisService) *AuthService {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = "your-default-super-secret-key" // A fallback secret for development
	}

	return &AuthService{
		jwtSecret:    []byte(secret),
		redisService: redisService,
	}
}

// GenerateToken creates a new signed JWT for a given user ID.
// The token is set to expire in 72 hours.
func (s *AuthService) GenerateToken(userID primitive.ObjectID) (string, error) {
	claims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 72)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}

// ValidateToken verifies a token's signature and checks if it has been blacklisted in Redis.
// It returns the token's claims if valid, otherwise returns an error.
func (s *AuthService) ValidateToken(tokenString string) (*Claims, error) {
	// 1. Check if the token is in the Redis blacklist.
	err := s.redisService.Client.Get(context.Background(), tokenString).Err()
	if err == nil {
		return nil, errors.New("token is blacklisted")
	}

	// 2. Proceed with JWT signature validation.
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return s.jwtSecret, nil
	})

	if err != nil || !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}

// InvalidateToken adds a token to the Redis blacklist to effectively log a user out.
// It sets a Time-To-Live (TTL) on the Redis key equal to the token's remaining validity,
// ensuring Redis doesn't store expired tokens indefinitely.
func (s *AuthService) InvalidateToken(tokenString string) error {
	claims := &Claims{}
	_, _, err := new(jwt.Parser).ParseUnverified(tokenString, claims)
	if err != nil {
		return errors.New("could not parse token claims")
	}

	// Calculate the token's remaining lifetime for the Redis TTL.
	ttl := time.Until(claims.ExpiresAt.Time)
	if ttl <= 0 {
		return errors.New("token already expired")
	}

	// Add the token to Redis with the calculated TTL.
	err = s.redisService.Client.Set(context.Background(), tokenString, "true", ttl).Err()
	return err
}
