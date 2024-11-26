package usecases

import (
	errorss "errors"
	"log"
	"mime/multipart"
	"net/http"
	models "user_authorization/domain"
	errors "user_authorization/error"
	"user_authorization/usecases/dto"
	"user_authorization/usecases/interfaces"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

//userUsecase Interface
type UserUseCaseI interface{
	CreateUser(user *dto.UserRegistrationDTO) (*dto.UserResponseDTO,*errors.CustomError)
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
}

// NewUserUsecase creates a new user usecase
func NewUserUsecase(userRepository interfaces.UserRepositoryI, jwtService interfaces.JWTServiceI, pwdService interfaces.HashingServiceI,fileUpload interfaces.FileUploadManagerI) *UserUsecase {
	return &UserUsecase{
		userRepository: userRepository,
		pwdService: pwdService,
		jwtService: jwtService,
		fileUploadManager: fileUpload,
	}
}

// CreateUser creates a new user
func (u *UserUsecase) CreateUser(user *dto.UserRegistrationDTO) (*dto.UserResponseDTO,*errors.CustomError) {
	existingUser, err := u.userRepository.GetUserByEmail(user.Email)
	if err != nil && !errorss.Is(err, gorm.ErrRecordNotFound) {
		return nil, errors.NewCustomError("Database error: "+err.Error(), http.StatusInternalServerError)
	}
	if existingUser != nil && existingUser.IsProviderSignIn == false {
		return nil, errors.NewCustomError("User already exists", 409)
	} else if (existingUser != nil && existingUser.IsProviderSignIn == true) {
		// Update the existing user
		Password,err := u.pwdService.HashPassword(user.Password)
		if err != nil {
			return nil, err
		}
		existingUser.Password = Password
		existingUser.FullName = user.FullName
		existingUser.PhoneNumber = user.PhoneNumber
		existingUser.IsProviderSignIn = false
		errs := u.userRepository.UpdateUser(existingUser.UserID.String(), existingUser)
		if (errs != nil) {
			return nil, errs
		}
		newUser := dto.UserResponseDTO{
			UserId: existingUser.UserID,
			FullName: existingUser.FullName,
			Email: existingUser.Email,
			Role: existingUser.Role,
			PhoneNumber: existingUser.PhoneNumber,
			IsProviderSignIn: existingUser.IsProviderSignIn,
			IsVerified: existingUser.IsVerified,
			ProfileImage: existingUser.ProfileImage,
			RefreshToken: existingUser.RefreshToken,
			AccessToken: existingUser.AccessToken,
		}
		return &newUser,nil


	}
	userId := uuid.New()
	Password,err := u.pwdService.HashPassword(user.Password)
	if err != nil {
		return nil, err
	}
	user.Password = Password
	userModel := models.User{
		UserID:      userId,
		FullName:    user.FullName,
		Email:       user.Email,
		Role:		"user",
		Password:    user.Password,
		PhoneNumber: user.PhoneNumber,
	}
	result, errs := u.userRepository.CreateUser(&userModel)
	if (errs != nil) {
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
	errs = u.userRepository.UpdateUser(userID, user)
	if errs != nil {
			deleteErr := u.fileUploadManager.DeleteFile(userID, file)
			if deleteErr != nil {
				log.Printf("Error rolling back uploaded image: %v", deleteErr)
			}
		return "", errors.NewCustomError(errs.Error(), errs.StatusCode)
		}
	// Return the image url
	return SecureURL, nil
}


