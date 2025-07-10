package database

import (
	"context"
	"fmt"
	"os"

	"github.com/redis/go-redis/v9"
)

type RedisService struct {
	Client *redis.Client
}

// NewRedisService initializes and returns a new RedisService.
func NewRedisService() (*RedisService, error) {
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379" // Default address
	}

	client := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: "", // No password set by default
		DB:       0,  // Default DB
	})

	// Ping Redis to ensure the connection is alive
	if _, err := client.Ping(context.Background()).Result(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &RedisService{Client: client}, nil
}

// Close gracefully closes the Redis connection.
func (s *RedisService) Close() {
	s.Client.Close()
}
