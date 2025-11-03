package router

import (
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"

	"example.com/pz10-auth/internal/core"
	"example.com/pz10-auth/internal/http/middleware"
	"example.com/pz10-auth/internal/platform/config"
	"example.com/pz10-auth/internal/platform/jwt"
	"example.com/pz10-auth/internal/repo"
)

func Build(cfg config.Config) http.Handler {
	r := chi.NewRouter()

	// DI
	userRepo := repo.NewUserMem()
	jwtv := jwt.NewHS256(cfg.JWTSecret)
	svc := core.NewService(userRepo, jwtv)

	// Публичные маршруты
	r.Post("/api/v1/login", svc.LoginHandler)
	r.Post("/api/v1/refresh", svc.RefreshHandler)
	r.Post("/api/v1/logout", svc.LogoutHandler)

	// Защищённые маршруты
	r.Group(func(priv chi.Router) {
		log.Println("Setting up protected routes with AuthN and AuthZRoles('admin', 'user')")
		priv.Use(middleware.AuthN(jwtv))
		priv.Use(middleware.AuthZRoles("admin", "user"))
		priv.Get("/api/v1/me", svc.MeHandler)
		priv.Get("/api/v1/users/{id}", svc.GetUserHandler)
	})

	// Только для админов
	r.Group(func(admin chi.Router) {
		log.Println("Setting up admin routes with AuthN and AuthZRoles('admin')")
		admin.Use(middleware.AuthN(jwtv))
		admin.Use(middleware.AuthZRoles("admin"))
		admin.Get("/api/v1/admin/stats", svc.AdminStats)
	})

	return r
}
