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
    TwoFactorAuth bool `gorm:"type:boolean;default:false"`
    CreatedAt        time.Time `gorm:"autoCreateTime"` 
    UpdatedAt        time.Time `gorm:"autoUpdateTime"` 
}

type Token struct {
	TokenID      uuid.UUID `gorm:"type:char(36);primaryKey"`
	RefreshToken string    `gorm:"type:text"`
	UserID       uuid.UUID  `gorm:"type:char(36)"`
	CreatedAt    time.Time `gorm:"autoCreateTime"`
	UpdatedAt    time.Time `gorm:"autoUpdateTime"`
}

// DB_CONNECTION_STRING is the connection string of the database


