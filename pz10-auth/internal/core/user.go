package core

type User struct {
	ID    int64
	Email string
	Role  string // "user" или "admin"
	// password_hash в репозитории, тут в домене можно не хранить
}
