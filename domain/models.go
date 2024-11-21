package models

import (
	_ "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
)

// User model
type User struct {
    UserId          uuid.UUID `json:"user_id" db:"user_id"`
    FullName        string    `json:"full_name" db:"full_name" validate:"required"`
    Email           string    `json:"email" db:"email" validate:"required,email"`
    Password        string    `json:"password" db:"password" validate:"required"`
    Role            string    `json:"role" db:"role" validate:"required,oneof=admin user"`
    PhoneNumber     string    `json:"phone_number" db:"phone_number"`
    IsProviderSignIn bool      `json:"is_provider_sign_in" db:"is_provider_sign_in"`
    IsVerified      bool      `json:"is_verified" db:"is_verified"`
    ProfileImage    string    `json:"profile_image" db:"profile_image"`
    RefreshToken    string    `json:"refresh_token" db:"refresh_token"`
    AccessToken     string    `json:"access_token" db:"access_token"`
}

// DB_CONNECTION_STRING is the connection string of the database


