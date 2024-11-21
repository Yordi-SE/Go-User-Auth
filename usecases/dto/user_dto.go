package dto

import "github.com/google/uuid"

// UserRegistrationDTO struct
type UserRegistrationDTO struct {
	FullName         string    `json:"full_name"`
	Email			string    `json:"email"`
	Password		 string    `json:"password"`
	ProfileImage  string	`json:"profile_image"`
	PhoneNumber string `json:"phone_number"`
}

// UserResponseDTO struct
type UserResponseDTO struct {
	UserId          uuid.UUID `json:"user_id"`
	FullName        string `json:"full_name"`
	Email           string `json:"email"`
	Role            string `json:"role"`
	PhoneNumber     string `json:"phone_number"`
	IsProviderSignIn bool   `json:"is_provider_sign_in"`
	IsVerified      bool   `json:"is_verified"`
	ProfileImage    string `json:"profile_image"`
	RefreshToken    string `json:"refresh_token"`
	AccessToken     string `json:"access_token"`
}
// UserLoginDTO struct
type UserLoginDTO struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// UserUpdateDTO struct
type UserUpdateDTO struct {
	FullName   string `json:"full_name"`
	ProfileImage string `json:"profile_image"`
	PhoneNumber string `json:"phone_number"`
}