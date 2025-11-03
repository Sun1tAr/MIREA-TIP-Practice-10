package repo

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

type UserRecord struct {
	ID    int64
	Email string
	Role  string
	Hash  []byte
}

type UserMem struct{ users map[string]UserRecord }

func NewUserMem() *UserMem {
	hash := func(s string) []byte { h, _ := bcrypt.GenerateFromPassword([]byte(s), bcrypt.DefaultCost); return h }
	return &UserMem{users: map[string]UserRecord{
		"admin@example.com": {ID: 1, Email: "admin@example.com", Role: "admin", Hash: hash("secret123")},
		"user@example.com":  {ID: 2, Email: "user@example.com", Role: "user", Hash: hash("secret123")},
		"user2@example.com": {ID: 3, Email: "user2@example.com", Role: "user", Hash: hash("secret123")}, // ← добавляем еще пользователя для тестов
	}}
}

var ErrNotFound = errors.New("user not found")
var ErrBadCreds = errors.New("bad credentials")

func (r *UserMem) ByEmail(email string) (UserRecord, error) {
	u, ok := r.users[email]
	if !ok {
		return UserRecord{}, ErrNotFound
	}
	return u, nil
}

func (r *UserMem) CheckPassword(email, pass string) (UserRecord, error) {
	u, err := r.ByEmail(email)
	if err != nil {
		return UserRecord{}, ErrNotFound
	}
	if bcrypt.CompareHashAndPassword(u.Hash, []byte(pass)) != nil {
		return UserRecord{}, ErrBadCreds
	}
	return u, nil
}

// Новый метод для получения пользователя по ID
func (r *UserMem) GetUserByID(id int64) (UserRecord, error) {
	for _, user := range r.users {
		if user.ID == id {
			return user, nil
		}
	}
	return UserRecord{}, ErrNotFound
}
