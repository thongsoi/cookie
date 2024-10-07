package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"text/template"

	"github.com/gorilla/sessions"
	"github.com/thongsoi/gorilla-sessions/models"
	"golang.org/x/crypto/bcrypt"
)

var tmpls *template.Template

func init() {
	tmpls = template.Must(template.ParseGlob("templates/*.html"))
}

// Serve the login.html template
func IndexHandler(w http.ResponseWriter, r *http.Request) {
	tmpls.ExecuteTemplate(w, "login.html", nil)
}

func LoginHandler(db *sql.DB, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Fetch user details by username
		user, err := models.GetUserByUsername(db, username)
		if err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		// Compare the hashed password
		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
		if err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		// Create a session and store the user ID
		session, err := store.Get(r, "session-name")
		if err != nil {
			http.Error(w, "Unable to create session", http.StatusInternalServerError)
			return
		}

		session.Values["userID"] = user.ID
		// Save the session
		if err := session.Save(r, w); err != nil {
			http.Error(w, "Unable to save session", http.StatusInternalServerError)
			return
		}

		// Login successful
		fmt.Fprint(w, "Logged in successfully")
	}
}

func LogoutHandler(store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Fetch the session
		session, err := store.Get(r, "session-name")
		if err != nil {
			http.Error(w, "Unable to fetch session", http.StatusInternalServerError)
			return
		}

		// Remove the user ID from the session
		delete(session.Values, "userID")

		// Save the session
		if err := session.Save(r, w); err != nil {
			http.Error(w, "Unable to save session", http.StatusInternalServerError)
			return
		}

		// Logout successful
		fmt.Fprint(w, "Logged out successfully")
	}
}

func ProtectedHandler(db *sql.DB, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Fetch the session
		session, err := store.Get(r, "session-name")
		if err != nil {
			http.Error(w, "Unable to fetch session", http.StatusInternalServerError)
			return
		}

		// Verify if the user ID is in the session
		userID, ok := session.Values["userID"].(int)
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Query the database to fetch the username
		var username string
		err = db.QueryRow("SELECT username FROM users2 WHERE id = $1", userID).Scan(&username)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "User not found", http.StatusUnauthorized)
			} else {
				http.Error(w, "Server error", http.StatusInternalServerError)
			}
			return
		}

		// If successful, welcome the user
		fmt.Fprintf(w, "Welcome, %s!", username)
	}
}
