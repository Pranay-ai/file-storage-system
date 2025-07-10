package users

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type UserHandler struct {
	userService UserServiceInterface
	jwtSecret   string
}

type UserServiceInterface interface {
	Register(ctx context.Context, user *User) error
	Login(ctx context.Context, email, password string) (*User, error)
}

type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

type RegisterRequest struct {
	Name     string `json:"name" validate:"required,min=2,max=50"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=6"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

type SuccessResponse struct {
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type LoginResponse struct {
	Token string `json:"token"`
	User  *User  `json:"user"`
}

func NewUserHandler(userService UserServiceInterface, jwtSecret string) *UserHandler {
	return &UserHandler{
		userService: userService,
		jwtSecret:   jwtSecret,
	}
}

func (uh *UserHandler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		uh.respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req RegisterRequest
	if err := uh.decodeJSON(r, &req); err != nil {
		uh.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := uh.validateRegisterRequest(&req); err != nil {
		uh.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	user := &User{
		Name:     req.Name,
		Email:    req.Email,
		Password: req.Password,
		Verified: false,
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := uh.userService.Register(ctx, user); err != nil {
		uh.handleServiceError(w, err)
		return
	}

	user.Password = ""
	uh.respondWithSuccess(w, http.StatusCreated, "user registered successfully", user)
}

func (uh *UserHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		uh.respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req LoginRequest
	if err := uh.decodeJSON(r, &req); err != nil {
		uh.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := uh.validateLoginRequest(&req); err != nil {
		uh.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	user, err := uh.userService.Login(ctx, req.Email, req.Password)
	if err != nil {
		uh.handleServiceError(w, err)
		return
	}

	token, err := uh.generateJWT(user)
	if err != nil {
		uh.respondWithError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	response := LoginResponse{
		Token: token,
		User:  user,
	}

	uh.respondWithSuccess(w, http.StatusOK, "login successful", response)
}

func (uh *UserHandler) decodeJSON(r *http.Request, v any) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(v)
}

func (uh *UserHandler) validateRegisterRequest(req *RegisterRequest) error {
	if req.Name == "" {
		return fmt.Errorf("name is required")
	}
	if len(req.Name) < 2 || len(req.Name) > 50 {
		return fmt.Errorf("name must be between 2 and 50 characters")
	}
	if req.Email == "" {
		return fmt.Errorf("email is required")
	}
	if req.Password == "" {
		return fmt.Errorf("password is required")
	}
	if len(req.Password) < 6 {
		return fmt.Errorf("password must be at least 6 characters")
	}
	return nil
}

func (uh *UserHandler) validateLoginRequest(req *LoginRequest) error {
	if req.Email == "" {
		return fmt.Errorf("email is required")
	}
	if req.Password == "" {
		return fmt.Errorf("password is required")
	}
	return nil
}

func (uh *UserHandler) generateJWT(user *User) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		UserID: user.ID.Hex(),
		Email:  user.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "file-storage-system",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(uh.jwtSecret))
}

func (uh *UserHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch err.Error() {
	case "user with this email already exists":
		uh.respondWithError(w, http.StatusConflict, err.Error())
	case "invalid credentials":
		uh.respondWithError(w, http.StatusUnauthorized, err.Error())
	default:
		uh.respondWithError(w, http.StatusInternalServerError, "internal server error")
	}
}

func (uh *UserHandler) respondWithError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := ErrorResponse{
		Error:   http.StatusText(statusCode),
		Message: message,
	}

	json.NewEncoder(w).Encode(response)
}

func (uh *UserHandler) respondWithSuccess(w http.ResponseWriter, statusCode int, message string, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := SuccessResponse{
		Message: message,
		Data:    data,
	}

	json.NewEncoder(w).Encode(response)
}

func (uh *UserHandler) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			uh.respondWithError(w, http.StatusUnauthorized, "authorization header required")
			return
		}

		if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
			tokenString = tokenString[7:]
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(uh.jwtSecret), nil
		})

		if err != nil || !token.Valid {
			uh.respondWithError(w, http.StatusUnauthorized, "invalid token")
			return
		}

		ctx := context.WithValue(r.Context(), "user_id", claims.UserID)
		ctx = context.WithValue(ctx, "email", claims.Email)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (uh *UserHandler) GetUserFromContext(r *http.Request) (string, string, error) {
	userID, ok := r.Context().Value("user_id").(string)
	if !ok {
		return "", "", fmt.Errorf("user_id not found in context")
	}

	email, ok := r.Context().Value("email").(string)
	if !ok {
		return "", "", fmt.Errorf("email not found in context")
	}

	return userID, email, nil
}

func (uh *UserHandler) Profile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		uh.respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	userID, email, err := uh.GetUserFromContext(r)
	if err != nil {
		uh.respondWithError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		uh.respondWithError(w, http.StatusBadRequest, "invalid user ID")
		return
	}

	user := &User{
		ID:    objectID,
		Email: email,
	}

	uh.respondWithSuccess(w, http.StatusOK, "user profile retrieved", user)
}
