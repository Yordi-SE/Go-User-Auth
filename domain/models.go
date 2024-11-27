package models

import (
	"time"

	"github.com/google/uuid"
)

// User model
type User struct {
    UserID           uuid.UUID `gorm:"type:char(36);primaryKey"`
    FullName         string    `gorm:"type:varchar(255);not null"`
    Email            string    `gorm:"type:varchar(255);unique;not null"`
    Password         string    `gorm:"type:varchar(255);not null"`
    Role             string    `gorm:"type:varchar(50);default:'user'"`
    PhoneNumber      string    `gorm:"type:varchar(15)"`
    IsProviderSignIn bool      `gorm:"type:boolean;default:false"`
    IsVerified       bool      `gorm:"type:boolean;default:false"`
    ProfileImage     string    `gorm:"type:varchar(255)"`
    RefreshToken     string    `gorm:"type:text"`
    AccessToken      string    `gorm:"type:text"`
    VerificationToken string    `gorm:"type:text"`
    CreatedAt        time.Time `gorm:"autoCreateTime"` // Automatically sets the time on insert
    UpdatedAt        time.Time `gorm:"autoUpdateTime"` // Automatically sets the time on update
}

// DB_CONNECTION_STRING is the connection string of the database


