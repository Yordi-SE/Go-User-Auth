package usecases

import (
	"net/http"
	errors "user_authorization/error"
	"user_authorization/usecases/dto"
	"user_authorization/usecases/interfaces"

	"github.com/golang-jwt/jwt/v5"
)

//UserAuthI

type UserAuthI interface {
	SignIn(user *dto.UserLoginDTO) (*dto.TokenDTO,*errors.CustomError)
	SignOut(userId string) error
	RefreshToken(refreshToken *dto.RefreshTokenDTO) (*dto.TokenDTO, *errors.CustomError)
	GetTokens(userId string) (*dto.TokenDTO, *errors.CustomError)
}

//UserAuth struct
type UserAuth struct {
	userRepository interfaces.UserRepositoryI
	pwdService     interfaces.HashingServiceI
	jwtService     interfaces.JWTServiceI
}


//NewUserAuth creates a new UserAuth
func NewUserAuth(userRepository interfaces.UserRepositoryI, pwdService interfaces.HashingServiceI, jwtService interfaces.JWTServiceI) *UserAuth {
	return &UserAuth{
		userRepository: userRepository,
		jwtService: jwtService,
		pwdService: pwdService,
	}
}




// Signup user
func (u *UserAuth) SignIn(user *dto.UserLoginDTO) (*dto.TokenDTO,*errors.CustomError) {

	result, err := u.userRepository.GetUserByEmail(user.Email)
	if err != nil {
		return nil, err
	}
	if !u.pwdService.ComparePassword(result.Password, user.Password) {
		return nil, err
	}

	accessToken, refreshToken, err := u.jwtService.Generate(result)
	if err != nil {
		return nil, err
	}
	err = u.userRepository.UpdateUserToken(result.UserID.String(), accessToken, refreshToken)
	if err != nil {
		return nil, err
	}
	token := dto.TokenDTO{
		AccessToken: accessToken,
		RefreshToken: refreshToken,
	}
	return &token, nil

}

// Signout user
func (u *UserAuth) SignOut(userId string) error {
	result, err := u.userRepository.GetUserById(userId)
	if err != nil {
		return err
	}
	err = u.userRepository.UpdateUserToken(result.UserID.String(), "","")
	if err != nil {
		return err

	}
	return nil
}

// Get tokens
func (u *UserAuth) GetTokens(userId string) (*dto.TokenDTO, *errors.CustomError) {
	// Get tokens
	result, err := u.userRepository.GetUserById(userId)
	if err != nil {
		return nil, err
	}
	token := dto.TokenDTO{
		AccessToken: result.AccessToken,
		RefreshToken: result.RefreshToken,

	}
	return &token, nil

}


// Refresh token
func (u *UserAuth) RefreshToken(refreshToken *dto.RefreshTokenDTO) (*dto.TokenDTO, *errors.CustomError) {
	// 
	token ,err := u.jwtService.ValidateRefreshToken(refreshToken.RefreshToken)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	email, ok := claims["email"].(string)
	if !ok {
		return nil, errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	user, err := u.userRepository.GetUserByEmail(email)
	if err != nil {
		return nil, err
	}
	token, err = u.jwtService.ValidateRefreshToken(user.RefreshToken)
	if err != nil {
		return nil, err
	}
	if user.RefreshToken != refreshToken.RefreshToken {
		return nil, errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	accessToken, refreshtoken,err := u.jwtService.Generate(user)
	if err != nil {
		return nil, err
	}
	err = u.userRepository.UpdateUserToken(user.UserID.String(), accessToken, refreshtoken)
	if err != nil {
		return nil, err
	}
	tokens := dto.TokenDTO{
		AccessToken: accessToken,
		RefreshToken: refreshtoken,
	}
	return &tokens, nil
}
