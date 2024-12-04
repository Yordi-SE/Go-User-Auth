package infrastructure

import (
	"time"
	models "user_authorization/domain"
	errors "user_authorization/error"

	"github.com/golang-jwt/jwt/v5"
)

// JWTManager struct
type JWTManager struct {
	AccessTokenSecretKey string
	RefreshTokenSecretKey string
	VerificationTokenSecretKey string
	PasswordResetSecretKey string
}


// NewJWTManager creates a new JWTManager
func NewJWTManager(AcessSecret, RefreshSecret string, VerificationSecret string,PasswordResetSecretKey string) *JWTManager {
	return &JWTManager{
		AccessTokenSecretKey: AcessSecret,
		RefreshTokenSecretKey: RefreshSecret,
		VerificationTokenSecretKey: VerificationSecret,
		PasswordResetSecretKey: PasswordResetSecretKey,
	}
}

// Generate generates a new JWT token
func (manager *JWTManager) Generate(user *models.User,refreshTokenId string) (string, string, *errors.CustomError ) {
	// Define JWT claims
	// Here, we are passing the user's email ID and Role as the claims
	
	claims := jwt.MapClaims{
		"email": user.Email,
		"role": user.Role,
		"user_id": user.UserID.String(),
		"exp": time.Now().Add(time.Minute * 1).Unix(),
	}


	AccessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := AccessToken.SignedString([]byte(manager.AccessTokenSecretKey))
	if err != nil {
		return "","", errors.NewCustomError("Error generating AccessToken", 500)
	}

	refreshClaims := jwt.MapClaims{
		"user_id": user.UserID.String(),
		"token_id": refreshTokenId,
		"exp": time.Now().Add(time.Hour * 72).Unix(),
		"email": user.Email,
		"role": user.Role,
	}

	RefreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := RefreshToken.SignedString([]byte(manager.RefreshTokenSecretKey))

	if err != nil {
		return "","", errors.NewCustomError("Error generation RefreshToken", 500)
	}
	return tokenString, refreshTokenString, nil
}


func (manager *JWTManager) ValidateAccessToken(token string) (*jwt.Token, *errors.CustomError ) {
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.NewCustomError("Unexpected signing method", 500)
		}
		return []byte(manager.AccessTokenSecretKey), nil
	})

	if err != nil {
		return nil, errors.NewCustomError(err.Error(), 500)
	}

	return parsedToken, nil
}

func (manager *JWTManager) ValidateRefreshToken(token string) (*jwt.Token, *errors.CustomError ) {
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.NewCustomError("Unexpected signing method", 500)
		}
		return []byte(manager.RefreshTokenSecretKey), nil
	})

	if err != nil {
		return nil, errors.NewCustomError(err.Error(), 500)
	}

	return parsedToken, nil
}

func (manager *JWTManager) FindClaim(token *jwt.Token) (jwt.MapClaims, bool) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, false
	}
	return claims, true
}


//Generate verification token
func (manager *JWTManager) GenerateVerificationToken(user *models.User) (string, *errors.CustomError) {
	claims := jwt.MapClaims{
		"user_id": user.UserID.String(),
		"exp": time.Now().Add(time.Hour * 1).Unix(),
	}

	verificationToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := verificationToken.SignedString([]byte(manager.VerificationTokenSecretKey))
	if err != nil {
		return "", errors.NewCustomError("Error generating verification token", 500)
	}
	return tokenString, nil

}

//Validate verification token
func (manager *JWTManager) ValidateVerificationToken(token string) (*jwt.Token, *errors.CustomError) {
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.NewCustomError("Unexpected signing method", 500)
		}
		return []byte(manager.VerificationTokenSecretKey), nil
	})

	if err != nil {
		return nil, errors.NewCustomError(err.Error(), 500)
	}

	return parsedToken, nil
}

// Generate reset password token
func (manager *JWTManager) GeneratePasswordResetToken(user *models.User) (string, *errors.CustomError) {
	claims := jwt.MapClaims{
		"user_id": user.UserID.String(),
		"exp": time.Now().Add(time.Hour * 1).Unix(),
	}
	passwordResetToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := passwordResetToken.SignedString([]byte(manager.PasswordResetSecretKey))
	if err != nil {
		return "", errors.NewCustomError("Error generating password reset token", 500)
	}
	return tokenString, nil

}

//validate password reset token
func (manager *JWTManager) ValidePasswordResetToken(token string) (*jwt.Token, *errors.CustomError) {
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.NewCustomError("Unexpected signing method", 500)
		}
		return []byte(manager.PasswordResetSecretKey), nil
	})

	if err != nil {
		return nil, errors.NewCustomError(err.Error(), 500)
	}

	return parsedToken, nil
}
