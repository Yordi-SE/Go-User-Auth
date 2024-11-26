package usecases

import (
	"context"
	"fmt"
	"log"
	"mime/multipart"
	"os"
	models "user_authorization/domain"
	errors "user_authorization/error"
	"user_authorization/usecases/dto"
	"user_authorization/usecases/interfaces"

	"github.com/cloudinary/cloudinary-go"
	"github.com/cloudinary/cloudinary-go/api/uploader"
	"github.com/google/uuid"
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
		ProfileImage: user.ProfileImage,
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
	CLOUDINARY_API_KEY := os.Getenv("CLOUDINARY_API_KEY")
	CLOUDINARY_API_SECRET := os.Getenv("CLOUDINARY_API_SECRET")
	CLOUDINARY_CLOUD_NAME := os.Getenv("CLOUDINARY_CLOUD_NAME")

 // Remove from local
 defer func() {
  os.Remove("../assets/uploads/" + file.Filename)
 }()

 user , errs := u.userRepository.GetUserById(userID)

 if errs != nil {
	  return "", errors.NewCustomError(errs.Error(), errs.StatusCode)
	}
 cloudinary_url := fmt.Sprintf("cloudinary://%s:%s@%s",CLOUDINARY_API_KEY,CLOUDINARY_API_SECRET,CLOUDINARY_CLOUD_NAME)
 cld, err := cloudinary.NewFromURL(cloudinary_url)

 // Upload the image on the cloud
 var ctx = context.Background()
 resp, err := cld.Upload.Upload(ctx, "../assets/uploads/"+file.Filename, uploader.UploadParams{PublicID: "go_auth_profile_pic" + "-" + file.Filename + "-" + userID})

 if err != nil {
  log.Fatal(err)
  return "", errors.NewCustomError(err.Error(), 500)
 }
 
user.ProfileImage = resp.SecureURL
 errs = u.userRepository.UpdateUser(userID, user)
 if errs != nil {
		_, deleteErr := cld.Upload.Destroy(ctx, uploader.DestroyParams{PublicID: "go_auth_profile_pic" + "-" + file.Filename + "-" + userID})
		if deleteErr != nil {
			log.Printf("Error rolling back uploaded image: %v", deleteErr)
		}
	  return "", errors.NewCustomError(errs.Error(), errs.StatusCode)
	}
 // Return the image url
 return resp.SecureURL, nil
}
