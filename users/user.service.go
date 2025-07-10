package users

import (
	"context"
	"errors"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"golang.org/x/crypto/bcrypt" // Import for password hashing
)

// The UserService is responsible for all business logic related to users.
type UserService struct {
	repository UserRepository
}

func NewUserService(db *mongo.Database) *UserService {
	return &UserService{
		repository: *NewUserRepository(db),
	}
}

// Register validates user data, hashes the password, and creates a new user.
func (us *UserService) Register(ctx context.Context, user *User) error {
	// 1. Check if a user with the email already exists
	existingUser, _ := us.repository.GetByEmail(ctx, user.Email)
	if existingUser != nil {
		return errors.New("user with this email already exists")
	}

	// 2. Hash the user's password for secure storage
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user.Password = string(hashedPassword)

	// 3. Create the user in the repository
	return us.repository.Create(ctx, user)
}

// Login verifies a user's credentials.
// It returns the user object on success so the handler can generate a token.
func (us *UserService) Login(ctx context.Context, email, password string) (*User, error) {
	// 1. Find the user by their email address
	user, err := us.repository.GetByEmail(ctx, email)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			// Use a generic error message for security
			return nil, errors.New("invalid credentials")
		}
		return nil, err
	}

	// 2. Compare the provided password with the stored hash
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		// Passwords do not match
		return nil, errors.New("invalid credentials")
	}

	// 3. On success, return the user object (excluding the password)
	user.Password = ""
	return user, nil
}
