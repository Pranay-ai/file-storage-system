package routes

import (
	"net/http"

	"github.com/Pranay-ai/file-storage-system/users"
)

type Router struct {
	userHandler *users.UserHandler
}

func NewRouter(userHandler *users.UserHandler) *Router {
	return &Router{
		userHandler: userHandler,
	}
}

func (r *Router) SetupRoutes() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", r.healthHandler)

	mux.HandleFunc("/api/users/register", r.userHandler.Register)
	mux.HandleFunc("/api/users/login", r.userHandler.Login)

	protectedMux := http.NewServeMux()
	protectedMux.HandleFunc("/api/users/profile", r.userHandler.Profile)

	mux.Handle("/api/users/profile", r.userHandler.AuthMiddleware(protectedMux))

	return mux
}

func (r *Router) healthHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "healthy"}`))
}