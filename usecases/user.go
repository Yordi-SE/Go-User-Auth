package usecases

import (
	models "user_authorization/domain"
	"user_authorization/usecases/dto"
	"user_authorization/usecases/interfaces"

	"github.com/google/uuid"
)

//userUsecase Interface
type UserUseCaseI interface{
	CreateUser(user *dto.UserRegistrationDTO) (*dto.UserResponseDTO,error)
	GetUsers(page int) ([]dto.UserRegistrationDTO, error)
	GetUserById(userId string) (*dto.UserRegistrationDTO, error) 
	UpdateUser(userId string, user *dto.UserRegistrationDTO) error
	DeleteUser(userId string) error
}


// UserUsecase struct
type UserUsecase struct {
	userRepository interfaces.UserRepositoryI
}

// NewUserUsecase creates a new user usecase
func NewUserUsecase(userRepository interfaces.UserRepositoryI) *UserUsecase {
	return &UserUsecase{
		userRepository: userRepository,
	}
}

// CreateUser creates a new user
func (u *UserUsecase) CreateUser(user *dto.UserRegistrationDTO) (*dto.UserResponseDTO,error) {
	userId := uuid.New()

	userModel := models.User{
		UserId:      userId,
		FullName:    user.FullName,
		Email:       user.Email,
		Role:		"user",
		Password:    user.Password,
		ProfileImage: user.ProfileImage,
		PhoneNumber: user.PhoneNumber,
	}
	result, err := u.userRepository.CreateUser(&userModel)
	if (err != nil) {
		return nil, err
	}

	newUser := dto.UserResponseDTO{
		UserId: result.UserId,
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
func (u *UserUsecase) GetUsers(page int) ([]dto.UserRegistrationDTO, error) {
	users, err := u.userRepository.GetUsers(page)
	if err != nil {
		return nil, err
	}
	userDTOs := []dto.UserRegistrationDTO{}
	for _, user := range users {
		userDTO := dto.UserRegistrationDTO{
			FullName:    user.FullName,
			Email:       user.Email,
			ProfileImage: user.ProfileImage,
			PhoneNumber: user.PhoneNumber,
		}
		userDTOs = append(userDTOs, userDTO)
	}
	return userDTOs, nil
}

// GetUserById gets a user by id
func (u *UserUsecase) GetUserById(userId string) (*dto.UserRegistrationDTO, error) {
	user, err := u.userRepository.GetUserById(userId)
	if err != nil {
		return nil, err
	}
	userDTO := dto.UserRegistrationDTO{
		FullName:    user.FullName,
		Email:       user.Email,
		Password:    user.Password,
		ProfileImage: user.ProfileImage,
		PhoneNumber: user.PhoneNumber,
	}
	return &userDTO, nil
}

// updateUser updates a user
func (u *UserUsecase) UpdateUser(userId string, user *dto.UserRegistrationDTO) error {
	userModel := models.User{
		FullName:    user.FullName,
		ProfileImage: user.ProfileImage,
		PhoneNumber: user.PhoneNumber,
	}
	return u.userRepository.UpdateUser(userId, &userModel)
}

//deleteUser deletes a user
func (u *UserUsecase) DeleteUser(userId string) error {
	return u.userRepository.DeleteUser(userId)
}


