package interfaces

import (
	models "user_authorization/domain"
)

// UserUsecase interface
type UserRepositoryI interface {
	CreateUser(user *models.User) (*models.User, error)
	GetUserByEmail(email string) (*models.User, error)
	GetUserById(userId string) (*models.User, error)
	DeleteUser(userId string) error
	GetUsers(page int) ([]models.User, error)
	UpdateUser(userId string, user *models.User) error
}