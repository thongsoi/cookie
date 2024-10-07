package models

import (
	"database/sql"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       int
	Username string
	Password string
}

func (u *User) Create(db *sql.DB) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.Password = string(hashedPassword)
	_, err = db.Exec("INSERT INTO users2 (username, password) VALUES ($1, $2)", u.Username, u.Password)
	return err
}

func GetUserByUsername(db *sql.DB, username string) (*User, error) {
	var user User
	err := db.QueryRow("SELECT id, username, password FROM users2 WHERE username = $1", username).
		Scan(&user.ID, &user.Username, &user.Password)
	if err != nil {
		return nil, err
	}
	return &user, nil
}
