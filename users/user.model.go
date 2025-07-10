package users

import "go.mongodb.org/mongo-driver/bson/primitive"

type User struct {
	ID        primitive.ObjectID  `bson:"_id,omitempty" json:"id"`
	Name      string              `bson:"name" json:"name"`
	Email     string              `bson:"email" json:"email"`
	Password  string              `bson:"password,omitempty" json:"-"`
	Verified  bool                `bson:"verified" json:"verified"`
	CreatedAt primitive.Timestamp `bson:"created_at" json:"created_at"`
	UpdatedAt primitive.Timestamp `bson:"updated_at" json:"updated_at"`
}
