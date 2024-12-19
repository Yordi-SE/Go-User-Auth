package models

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// User model
type User struct {
    gorm.Model
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
} 




