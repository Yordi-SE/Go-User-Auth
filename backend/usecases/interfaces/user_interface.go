package interfaces

import (
	"mime/multipart"
	"time"
	models "user_authorization/domain"

	"github.com/golang-jwt/jwt/v5"

	errors "user_authorization/error"
)

// UserUsecase interface
type UserRepositoryI interface {
	CreateUser(user *models.User) (*models.User, *errors.CustomError)
	GetUserById(userId string) (*models.User, *errors.CustomError)
	DeleteUser(userId string) *errors.CustomError
	GetUserByEmail(email string) (*models.User, *errors.CustomError)
	GetUsers(page int) ([]models.User, *errors.CustomError)
	SaveUserUpdate(user *models.User) *errors.CustomError
}



type HashingServiceI interface {
	 HashPassword(password string) (string, *errors.CustomError)
	ComparePassword(hashedPassword string, password string) bool
}

type JWTServiceI interface {
	 Generate(user *models.User,refreshTokenId string) (string, string, *errors.CustomError )
	ValidateAccessToken(token string) (*jwt.Token, *errors.CustomError )
	ValidateRefreshToken(token string) (*jwt.Token, *errors.CustomError)
	FindClaim(token *jwt.Token) (jwt.MapClaims, bool)
	GenerateVerificationToken(user *models.User) (string, *errors.CustomError)
	ValidateVerificationToken(token string) (*jwt.Token, *errors.CustomError)
	ValidePasswordResetToken(token string) (*jwt.Token, *errors.CustomError)
	GeneratePasswordResetToken(user *models.User) (string, *errors.CustomError)
	GenerateOtpToken(user *models.User) (string, *errors.CustomError)
	ValidateOtpToken(token string) (*jwt.Token, *errors.CustomError)
GenerateProviderToken(user *models.User) (string, *errors.CustomError)
ValidateProviderToken(token string) (*jwt.Token, *errors.CustomError) 
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

type CacheRepositoryI interface {
	Set(key string, value string, expiry_time time.Duration) *errors.CustomError
	Get(key string) (string, *errors.CustomError) 
	Delete(key string) *errors.CustomError 
}