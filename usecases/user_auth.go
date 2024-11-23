package usecases

import (
	errors "user_authorization/error"
	"user_authorization/usecases/dto"
	"user_authorization/usecases/interfaces"
)

//UserAuthI

type UserAuthI interface {
	SignIn(user *dto.UserLoginDTO) (*dto.TokenDTO,*errors.CustomError)
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