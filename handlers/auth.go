package handlers

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/thongsoi/gorilla-sessions/models"

	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

func LoginHandler(db *sql.DB, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := r.FormValue("username")
		password := r.FormValue("password")

		user, err := models.GetUserByUsername(db, username)
		if err != nil || bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		session, _ := store.Get(r, "session-name")
		session.Values["userID"] = user.ID
		session.Save(r, w)

		fmt.Fprint(w, "Logged in successfully")
	}
}

func LogoutHandler(store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session-name")
		delete(session.Values, "userID")
		session.Save(r, w)
		fmt.Fprint(w, "Logged out successfully")
	}
}

func ProtectedHandler(db *sql.DB, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session-name")
		userID, ok := session.Values["userID"].(int)
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		var username string
		err := db.QueryRow("SELECT username FROM users2 WHERE id = $1", userID).Scan(&username)
		if err != nil {
			http.Error(w, "User not found", http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(w, "Welcome, %s!", username)
	}
}
