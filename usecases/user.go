package usecases

import (
	models "user_authorization/domain"
	errors "user_authorization/error"
	"user_authorization/usecases/dto"
	"user_authorization/usecases/interfaces"

	"github.com/google/uuid"
)

//userUsecase Interface
type UserUseCaseI interface{
	CreateUser(user *dto.UserRegistrationDTO) (*dto.UserResponseDTO,*errors.CustomError)
	GetUsers(page int) ([]dto.UserResponseDTO, *errors.CustomError)
	GetUserById(userId string) (*dto.UserResponseDTO, *errors.CustomError) 
	UpdateUser(userId string, user *dto.UserUpdateDTO) *errors.CustomError
DeleteUser(userId string) *errors.CustomError
}


// UserUsecase struct
type UserUsecase struct {
	userRepository interfaces.UserRepositoryI
	pwdService interfaces.HashingServiceI
	jwtService interfaces.JWTServiceI
}

// NewUserUsecase creates a new user usecase
func NewUserUsecase(userRepository interfaces.UserRepositoryI, jwtService interfaces.JWTServiceI, pwdService interfaces.HashingServiceI) *UserUsecase {
	return &UserUsecase{
		userRepository: userRepository,
		pwdService: pwdService,
		jwtService: jwtService,
	}
}

// CreateUser creates a new user
func (u *UserUsecase) CreateUser(user *dto.UserRegistrationDTO) (*dto.UserResponseDTO,*errors.CustomError) {
	userId := uuid.New()
	Password,err := u.pwdService.HashPassword(user.Password)
	user.Password = Password
	userModel := models.User{
		UserID:      userId,
		FullName:    user.FullName,
		Email:       user.Email,
		Role:		"user",
		Password:    user.Password,
		ProfileImage: user.ProfileImage,
		PhoneNumber: user.PhoneNumber,
	}
	result, errs := u.userRepository.CreateUser(&userModel)
	if (err != nil) {
		return nil, errs
	}
	newUser := dto.UserResponseDTO{
		UserId: result.UserID,
		FullName: result.FullName,
		Email: result.Email,
		Role: result.Role,
		PhoneNumber: result.PhoneNumber,
		IsProviderSignIn: result.IsProviderSignIn,
		IsVerified: result.IsVerified,
		ProfileImage: result.ProfileImage,
		RefreshToken: result.RefreshToken,
		AccessToken: result.AccessToken,
	}
	return &newUser,nil
}

//GetUsers gets 20 users per page
func (u *UserUsecase) GetUsers(page int) ([]dto.UserResponseDTO, *errors.CustomError) {
	users, err := u.userRepository.GetUsers(page)
	if err != nil {
		return nil, err
	}
	userDTOs := []dto.UserResponseDTO{}
	for _, user := range users {
		userDTO := dto.UserResponseDTO{
			UserId: user.UserID,
			FullName:    user.FullName,
			Email:       user.Email,
			ProfileImage: user.ProfileImage,
			PhoneNumber: user.PhoneNumber,
			Role: user.Role,
			IsProviderSignIn: user.IsProviderSignIn,
			IsVerified: user.IsVerified,
			RefreshToken: user.RefreshToken,
			AccessToken: user.AccessToken,


		}
		userDTOs = append(userDTOs, userDTO)
	}
	return userDTOs, nil
}

// GetUserById gets a user by id
func (u *UserUsecase) GetUserById(userId string) (*dto.UserResponseDTO, *errors.CustomError) {
	user, err := u.userRepository.GetUserById(userId)
	if err != nil {
		return nil, err
	}
		userDTO := dto.UserResponseDTO{
			UserId: user.UserID,
			FullName:    user.FullName,
			Email:       user.Email,
			ProfileImage: user.ProfileImage,
			PhoneNumber: user.PhoneNumber,
			Role: user.Role,
			IsProviderSignIn: user.IsProviderSignIn,
			IsVerified: user.IsVerified,
			RefreshToken: user.RefreshToken,
			AccessToken: user.AccessToken,
		}
	return &userDTO, nil
}

// updateUser updates a user
func (u *UserUsecase) UpdateUser(userId string, user *dto.UserUpdateDTO) *errors.CustomError {
	userModel := models.User{
		FullName:    user.FullName,
		ProfileImage: user.ProfileImage,
		PhoneNumber: user.PhoneNumber,
	}
	return u.userRepository.UpdateUser(userId, &userModel)
}

//deleteUser deletes a user
func (u *UserUsecase) DeleteUser(userId string) *errors.CustomError {
	return u.userRepository.DeleteUser(userId)
}


