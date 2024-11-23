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
}


// NewJWTManager creates a new JWTManager
func NewJWTManager(AcessSecret, RefreshSecret string) *JWTManager {
	return &JWTManager{
		AccessTokenSecretKey: AcessSecret,
		RefreshTokenSecretKey: RefreshSecret,
	}
}

// Generate generates a new JWT token
func (manager *JWTManager) Generate(user *models.User) (string, string, *errors.CustomError ) {
	// Define JWT claims
	// Here, we are passing the user's email ID and Role as the claims
	
	claims := jwt.MapClaims{
		"email": user.Email,
		"role": user.Role,
		"user_id": user.UserID,
		"exp": time.Now().Add(time.Hour * 1).Unix(),
	}


	AccessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := AccessToken.SignedString([]byte(manager.AccessTokenSecretKey))
	if err != nil {
		return "","", errors.NewCustomError("Error generating AccessToken", 500)
	}

	refreshClaims := jwt.MapClaims{
		"user_id": user.UserID,
		"exp": time.Now().Add(time.Hour * 24).Unix(),
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
		return nil, errors.NewCustomError("Error parsing token", 500)
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
		return nil, errors.NewCustomError("Error parsing token", 500)
	}

	return parsedToken, nil
}


//