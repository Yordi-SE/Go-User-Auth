package usecases

import (
	"log"
	"mime/multipart"
	errors "user_authorization/error"
	"user_authorization/usecases/dto"
	"user_authorization/usecases/interfaces"
)

//userUsecase Interface
type UserUseCaseI interface{
	GetUsers(page int) ([]dto.UserResponseDTO, *errors.CustomError)
	GetUserById(userId string) (*dto.UserResponseDTO, *errors.CustomError) 
	UpdateUser(userId string, user *dto.UserUpdateDTO) *errors.CustomError
	UploadProfilePic(userID string,file *multipart.FileHeader) (string, *errors.CustomError)
	DeleteUser(userId string) *errors.CustomError
}


// UserUsecase struct
type UserUsecase struct {
	userRepository interfaces.UserRepositoryI
	pwdService interfaces.HashingServiceI
	jwtService interfaces.JWTServiceI
	fileUploadManager interfaces.FileUploadManagerI
	tokenRepository interfaces.TokenRepositoryI
}

// NewUserUsecase creates a new user usecase
func NewUserUsecase(userRepository interfaces.UserRepositoryI, jwtService interfaces.JWTServiceI, pwdService interfaces.HashingServiceI,fileUpload interfaces.FileUploadManagerI, token interfaces.TokenRepositoryI) *UserUsecase {
	return &UserUsecase{
		userRepository: userRepository,
		pwdService: pwdService,
		jwtService: jwtService,
		fileUploadManager: fileUpload,
		tokenRepository: token,
	}
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
	existingUser,err := u.userRepository.GetUserById(userId)
	if err != nil {
		return err
	}
	if user.FullName != "" {
        existingUser.FullName = user.FullName
    }
    if user.PhoneNumber != "" {
        existingUser.PhoneNumber = user.PhoneNumber
    }
    if user.ProfileImage != "" {
        existingUser.ProfileImage = user.ProfileImage
    }
	return u.userRepository.SaveUserUpdate(existingUser)
}

//deleteUser deletes a user
func (u *UserUsecase) DeleteUser(userId string) *errors.CustomError {
	return u.userRepository.DeleteUser(userId)
}

// Uploade profile image
func (u *UserUsecase) UploadProfilePic(userID string,file *multipart.FileHeader) (string, *errors.CustomError) {

	user , errs := u.userRepository.GetUserById(userID)

	if errs != nil {
		return "", errors.NewCustomError(errs.Error(), errs.StatusCode)
	}


	SecureURL, err := u.fileUploadManager.UploadFile(userID,file)

	if err != nil {
		return "", errors.NewCustomError(err.Error(), 500)
	}
	
	user.ProfileImage = SecureURL
	errs = u.userRepository.SaveUserUpdate(user)
	if errs != nil {
			deleteErr := u.fileUploadManager.DeleteFile(userID, file)
			if deleteErr != nil {
				log.Printf("Error rolling back uploaded image: %v", deleteErr)
			}
		return "", errors.NewCustomError(errs.Error(), errs.StatusCode)
	}
	return SecureURL, nil
}


