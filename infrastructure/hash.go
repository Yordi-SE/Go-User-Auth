package infrastructure

import (
	errors "user_authorization/error"

	"golang.org/x/crypto/bcrypt"
)

type HashingService struct {
}

func NewHashingService() *HashingService {
	return &HashingService{}
}

func (h *HashingService) HashPassword(password string) (string, *errors.CustomError) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", errors.NewCustomError("error hashing password", 500)
	}
	return string(hashedPassword), nil
}


func (h *HashingService) ComparePassword(hashedPassword string, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}