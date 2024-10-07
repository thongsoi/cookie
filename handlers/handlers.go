package handlers

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

func IndexHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Welcome to the index page!")
}

func LoginHandler(db *sql.DB, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := r.FormValue("username")
		password := r.FormValue("password")

		var storedPassword string
		var userID int
		err := db.QueryRow("SELECT id, password FROM users2 WHERE username = $1", username).Scan(&userID, &storedPassword)
		if err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password))
		if err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		session, err := store.Get(r, "session-name")
		if err != nil {
			http.Error(w, "Session error", http.StatusInternalServerError)
			return
		}

		session.Values["userID"] = userID
		err = session.Save(r, w)
		if err != nil {
			http.Error(w, "Session save error", http.StatusInternalServerError)
			return
		}

		fmt.Fprint(w, "Logged in successfully")
	}
}

func LogoutHandler(store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "session-name")
		if err != nil {
			http.Error(w, "Session error", http.StatusInternalServerError)
			return
		}

		delete(session.Values, "userID")
		err = session.Save(r, w)
		if err != nil {
			http.Error(w, "Session save error", http.StatusInternalServerError)
			return
		}

		fmt.Fprint(w, "Logged out successfully")
	}
}

func ProtectedHandler(db *sql.DB, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "session-name")
		if err != nil {
			http.Error(w, "Session error", http.StatusInternalServerError)
			return
		}

		userID, ok := session.Values["userID"].(int)
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		var username string
		err = db.QueryRow("SELECT username FROM users2 WHERE id = $1", userID).Scan(&username)
		if err != nil {
			http.Error(w, "User not found", http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(w, "Welcome, %s!", username)
	}
}
