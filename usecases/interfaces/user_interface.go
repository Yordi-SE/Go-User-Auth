package interfaces

import (
	"mime/multipart"
	models "user_authorization/domain"

	"github.com/golang-jwt/jwt/v5"

	errors "user_authorization/error"
)

// UserUsecase interface
type UserRepositoryI interface {
	CreateUser(user *models.User) (*models.User, *errors.CustomError)
	GetUserById(userId string) (*models.User, *errors.CustomError)
	UpdateUserToken(userId string, accessToken string, refreshToken string) *errors.CustomError 
	DeleteUser(userId string) *errors.CustomError
	GetUserByEmail(email string) (*models.User, *errors.CustomError)
	GetUsers(page int) ([]models.User, *errors.CustomError)
	UpdateUser(userId string, user *models.User) *errors.CustomError
	UpdateUserVerificationStatus(userId string,  user *models.User) *errors.CustomError
}

type HashingServiceI interface {
	 HashPassword(password string) (string, *errors.CustomError)
	ComparePassword(hashedPassword string, password string) bool
}

type JWTServiceI interface {
	Generate(user *models.User) (string, string, *errors.CustomError )
	ValidateAccessToken(token string) (*jwt.Token, *errors.CustomError )
	ValidateRefreshToken(token string) (*jwt.Token, *errors.CustomError)
	FindClaim(token *jwt.Token) (jwt.MapClaims, bool)
	GenerateVerificationToken(user *models.User) (string, *errors.CustomError)
	ValidateVerificationToken(token string) (*jwt.Token, *errors.CustomError)
}

type FileUploadManagerI interface {
 	UploadFile(userID string,file *multipart.FileHeader) (string, *errors.CustomError)
 	DeleteFile(userID string, file *multipart.FileHeader) *errors.CustomError
}

type EmailServiceI interface {
	SendEmail(email string, subject string, body string,from string) error
	GenerateOTP(length int) (string, error)
	GetOTPEmailBody(otpCode string,file_name string) (string, error) 
}