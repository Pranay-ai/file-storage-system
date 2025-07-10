package main

import (
	"log"
	"net/http"
	"os"

	"github.com/Pranay-ai/file-storage-system/database"
	"github.com/Pranay-ai/file-storage-system/users"
	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found or error loading .env file:", err)
	}

	log.Println("Starting file storage system server...")

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "your-secret-key-change-this-in-production"
		log.Println("JWT_SECRET not set, using default (change this in production)")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
		log.Println("PORT not set, using default:", port)
	}

	dbName := os.Getenv("DB_NAME")
	if dbName == "" {
		dbName = "file_storage_system"
		log.Println("DB_NAME not set, using default:", dbName)
	}

	mongoService, err := database.NewMongoService(dbName)
	if err != nil {
		log.Fatal("Failed to connect to MongoDB:", err)
	}
	defer func() {
		if err := mongoService.Disconnect(); err != nil {
			log.Printf("Error disconnecting from MongoDB: %v", err)
		}
	}()

	userService := users.NewUserService(mongoService.Database)
	userHandler := users.NewUserHandler(userService, jwtSecret)

	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "healthy"}`))
	})

	mux.HandleFunc("/api/users/register", userHandler.Register)
	mux.HandleFunc("/api/users/login", userHandler.Login)

	protectedMux := http.NewServeMux()
	protectedMux.HandleFunc("/api/users/profile", userHandler.Profile)

	mux.Handle("/api/users/profile", userHandler.AuthMiddleware(protectedMux))

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	log.Printf("Server starting on port %s", port)
	log.Printf("Health check available at: http://localhost:%s/health", port)
	log.Printf("API endpoints:")
	log.Printf("  POST /api/users/register - Register a new user")
	log.Printf("  POST /api/users/login - Login user")
	log.Printf("  GET /api/users/profile - Get user profile (requires auth)")

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal("Server failed to start:", err)
	}
}
