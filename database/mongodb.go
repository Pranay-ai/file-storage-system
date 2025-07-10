package database

import (
	"context"
	"log"
	"os"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type MongoService struct {
	Client   *mongo.Client
	Database *mongo.Database
}

// NewMongoService creates a new MongoService, connects to the DB, and returns the instance
func NewMongoService(dbName string) (*MongoService, error) {
	var uri string
	if uri = os.Getenv("MONGODB_URI"); uri == "" {
		uri = "mongodb://localhost:27017"
		log.Println("MONGODB_URI not set, using default:", uri)
	}

	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
	opts := options.Client().ApplyURI(uri).SetServerAPIOptions(serverAPI)

	client, err := mongo.Connect(opts)
	if err != nil {
		return nil, err
	}

	// Ping to verify connection
	if err := client.Ping(context.TODO(), nil); err != nil {
		return nil, err
	}

	log.Println("Successfully connected to MongoDB!")

	db := client.Database(dbName)

	return &MongoService{
		Client:   client,
		Database: db,
	}, nil
}

// Disconnect closes the MongoDB client connection
func (ms *MongoService) Disconnect() error {
	if ms.Client != nil {
		return ms.Client.Disconnect(context.TODO())
	}
	return nil
}
