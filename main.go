package main

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/thongsoi/gorilla-sessions/handlers"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/lib/pq"
)

var db *sql.DB
var store = sessions.NewCookieStore([]byte("super-secret-key"))

func init() {
	var err error
	db, err = sql.Open("postgres", "postgres://dev1:dev1pg@localhost/biomassx?sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/login", handlers.LoginHandler(db, store)).Methods("POST")
	r.HandleFunc("/logout", handlers.LogoutHandler(store)).Methods("POST")
	r.HandleFunc("/protected", handlers.ProtectedHandler(db, store)).Methods("GET")

	http.Handle("/", r)
	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
