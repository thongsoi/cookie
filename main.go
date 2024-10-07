package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/lib/pq"
	"github.com/thongsoi/gorilla-sessions/handlers"
)

var db *sql.DB
var store *sessions.CookieStore

func init() {
	var err error

	// Initialize database connection
	db, err = sql.Open("postgres", "postgres://dev1:dev1pg@localhost/biomassx?sslmode=disable")
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Test the connection
	err = db.Ping()
	if err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	// Initialize session store (better to use environment variable for the secret key)
	secretKey := os.Getenv("SESSION_KEY")
	if secretKey == "" {
		log.Fatal("SESSION_KEY environment variable not set")
	}
	store = sessions.NewCookieStore([]byte(secretKey))
}

func main() {
	// Ensure the database connection is closed when the application exits
	defer db.Close()

	r := mux.NewRouter()
	r.HandleFunc("/", handlers.IndexHandler).Methods("GET")
	r.HandleFunc("/login", handlers.LoginHandler(db, store)).Methods("POST")
	r.HandleFunc("/logout", handlers.LogoutHandler(store)).Methods("POST")
	r.HandleFunc("/protected", handlers.ProtectedHandler(db, store)).Methods("GET")

	http.Handle("/", r)
	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
