package models

import (
	"database/sql"
	"errors"
	"log"

	"golang.org/x/crypto/bcrypt"
)

// User represents the structure of a user in the system
type User struct {
	ID       int
	Username string
	Password string
}

// Create hashes the password and inserts the user into the database
func (u *User) Create(db *sql.DB) error {
	// Hash the user's password
	hashedPassword, err := HashPassword(u.Password)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		return err
	}

	u.Password = hashedPassword

	// Insert the new user into the users2 table
	_, err = db.Exec("INSERT INTO users2 (username, password) VALUES ($1, $2)", u.Username, u.Password)
	if err != nil {
		log.Printf("Error inserting user into database: %v", err)
		return err
	}

	return nil
}

// HashPassword generates a bcrypt hash of the password
func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error generating bcrypt hash: %v", err)
		return "", err
	}
	return string(hashedPassword), nil
}

// GetUserByUsername fetches a user by their username from the database
func GetUserByUsername(db *sql.DB, username string) (*User, error) {
	var user User

	// Query for the user by their username
	err := db.QueryRow("SELECT id, username, password FROM users2 WHERE username = $1", username).
		Scan(&user.ID, &user.Username, &user.Password)

	// If no rows are returned, handle the error
	if err == sql.ErrNoRows {
		log.Printf("User not found: %v", err)
		return nil, errors.New("user not found")
	} else if err != nil {
		log.Printf("Database error: %v", err)
		return nil, err
	}

	return &user, nil
}
