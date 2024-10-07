package main

import (
	"database/sql"
	"log"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	// Initialize database connection
	db, err := sql.Open("postgres", "postgres://dev1:dev1pg@localhost/biomassx?sslmode=disable")
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Test the connection
	err = db.Ping()
	if err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	// Hash the password
	password := "dev1pg"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Error hashing password: %v", err)
	}

	// Update the user's password in the database
	_, err = db.Exec("UPDATE users2 SET password = $1 WHERE username = $2", string(hashedPassword), "dev1")
	if err != nil {
		log.Fatalf("Error updating password: %v", err)
	}

	log.Println("Password updated successfully")
}
