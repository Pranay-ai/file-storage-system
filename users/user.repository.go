package users

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

type UserRepository struct {
	collObj *mongo.Collection
}

func NewUserRepository(db *mongo.Database) *UserRepository {
	return &UserRepository{
		collObj: db.Collection("users"),
	}
}

// Create a new user
func (ur *UserRepository) Create(ctx context.Context, user *User) error {
	user.ID = primitive.NewObjectID()
	user.CreatedAt = primitive.Timestamp{T: uint32(time.Now().Unix())}
	user.UpdatedAt = user.CreatedAt
	_, err := ur.collObj.InsertOne(ctx, user)
	return err
}

// Get user by ID
func (ur *UserRepository) GetByID(ctx context.Context, id primitive.ObjectID) (*User, error) {
	var user User
	err := ur.collObj.FindOne(ctx, bson.M{"_id": id}).Decode(&user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// Get user by email
func (ur *UserRepository) GetByEmail(ctx context.Context, email string) (*User, error) {
	var user User
	err := ur.collObj.FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// Update user fields
func (ur *UserRepository) Update(ctx context.Context, id primitive.ObjectID, update bson.M) error {
	update["updated_at"] = primitive.Timestamp{T: uint32(time.Now().Unix())}
	_, err := ur.collObj.UpdateOne(ctx, bson.M{"_id": id}, bson.M{"$set": update})
	return err
}

// Delete user
func (ur *UserRepository) Delete(ctx context.Context, id primitive.ObjectID) error {
	_, err := ur.collObj.DeleteOne(ctx, bson.M{"_id": id})
	return err
}
