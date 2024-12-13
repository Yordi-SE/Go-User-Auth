package usecase_test

import (
	"log"
	"os"
	"strings"
	"testing"
	models "user_authorization/domain"
	"user_authorization/infrastructure"
	"user_authorization/repositories"
	"user_authorization/test/mocks"
	"user_authorization/usecases"
	"user_authorization/usecases/dto"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/joho/godotenv"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)


type UserAuthTest struct {
	suite.Suite
	UserRepository    *repositories.UserRepository
	HashingService    *infrastructure.HashingService
	JwtService       *infrastructure.JWTManager
	MockFileUploadManager *mocks.FileUploadManagerI
	TokenRepository   *repositories.TokenRepository
	MockEmailService      *mocks.EmailServiceI
	UserUsecase *usecases.UserUsecase
	UserAuthCase *usecases.UserAuth
	DB *gorm.DB
}

func (suite *UserAuthTest) SetupTest() {
	err := godotenv.Load("../../.env")
	if err != nil {
		log.Fatal("Error loading .env file",err)
	}
    db, err := gorm.Open(mysql.Open(os.Getenv("DB_TEST_CONNECTION_STRING")), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database", err)
	}
    db.AutoMigrate(&models.User{})
	db.AutoMigrate(&models.Token{})
	suite.DB = db
	suite.JwtService = infrastructure.NewJWTManager(os.Getenv("ACCESS_SECRET"), os.Getenv("REFRESH_SECRET"), os.Getenv("VERIFICATION_SECRET"),os.Getenv("PASSWORD_RESET_TOKEN"),os.Getenv("OTP_SECRET"))
	suite.HashingService = infrastructure.NewHashingService()
	suite.MockFileUploadManager = new(mocks.FileUploadManagerI)
	suite.MockEmailService = new(mocks.EmailServiceI)
	suite.UserRepository = repositories.NewUserRepository(db)
	suite.TokenRepository = repositories.NewTokenRepository(db)
	suite.UserUsecase = usecases.NewUserUsecase(suite.UserRepository, suite.JwtService, suite.HashingService, suite.MockFileUploadManager, suite.TokenRepository)
	suite.UserAuthCase = usecases.NewUserAuth(suite.UserRepository,  suite.HashingService, suite.JwtService, suite.MockEmailService, suite.TokenRepository, os.Getenv("TwO_FACTOR_SECRET"))
}

func (suite *UserAuthTest) TearDownTest() {
	if err := suite.DB.Exec("TRUNCATE TABLE users").Error; err != nil {
		suite.T().Fatal("Failed to truncate users table", err)
}

	if err := suite.DB.Exec("TRUNCATE TABLE tokens").Error; err != nil {
		suite.T().Fatal("Failed to truncate tokens table", err)
	}
}


func (suite *UserAuthTest) TestCreateUser() {
	user := models.User{
        FullName:          "Jane Doe",
        Email:             "jane@example.com",
        IsVerified:        false,
        IsProviderSignIn:  false,
        PhoneNumber:       "1234567890",

    }
    suite.MockEmailService.On(
        "GetOTPEmailBody",
        mock.MatchedBy(func(arg string) bool {
            return strings.HasPrefix(arg, "localhost:8080") 
        }),
        mock.MatchedBy(func(arg string) bool {
            return arg == "otp_template.html" 
        }),
    ).Return("email body", nil)
    suite.MockEmailService.On(
        "SendEmail",
        user.Email,          
        "Email Verification", 
        "email body",        
        "go_auth@gmail.com", 
    ).Return(nil)

	response,err := suite.UserAuthCase.CreateUser(&dto.UserRegistrationDTO{
		FullName:    user.FullName,
		Email:       user.Email,
		Password:    user.Password,
		PhoneNumber: user.PhoneNumber,
	})

	if err != nil {	
		suite.Fail("Failed to create user")
	}

	suite.Equal(response.Email, user.Email)
	suite.Equal(response.FullName, user.FullName)
	suite.Equal(response.PhoneNumber, user.PhoneNumber)
	suite.Equal(response.IsVerified, user.IsVerified)
	suite.Equal(response.IsProviderSignIn, user.IsProviderSignIn)
	suite.Equal(response.Role, "user")
	suite.Equal(response.IsProviderSignIn, false)
	suite.Equal(response.IsVerified, false)
	

	suite.MockEmailService.AssertExpectations(suite.T())
}

//user already exists
func (suite *UserAuthTest) TestCreateUser_Exists() {
	user := models.User{
		FullName:          "Jane Doe",
		Email:             "",
		IsVerified:        false,
		IsProviderSignIn:  false,
		PhoneNumber:       "1234567890",
	}
	_,err  := suite.UserRepository.CreateUser(&user)
	if err != nil {
		suite.Fail("Failed to create user")
	}
	_,err = suite.UserAuthCase.CreateUser(&dto.UserRegistrationDTO{
		FullName:    user.FullName,
		Email:       user.Email,

		PhoneNumber: user.PhoneNumber,
	})	
	suite.Equal(err.Error(),"User already exists")
	suite.Equal(err.StatusCode, 400)
}

func (suite *UserAuthTest) TestLoginUser() {
	password, err := suite.HashingService.HashPassword("password")
	if err != nil {
		suite.Fail("Failed to hash password")
	}
	user := models.User{
		FullName:          "Jane Doe",
		Email:            "jane@example.com",
		IsVerified:        true,
		IsProviderSignIn:  false,
		PhoneNumber:       "1234567890",
		Password:          password,
 
	}
	_,err  = suite.UserRepository.CreateUser(&user)
	if err != nil {
		suite.Fail("Failed to create user")
	}
	
	response, err := suite.UserAuthCase.SignIn(&dto.UserLoginDTO{
		Email:    user.Email,
		Password: "password",
	})

	if err != nil {
		suite.Fail("Failed to login user")
	}

	token ,err := suite.JwtService.ValidateRefreshToken(response.RefreshToken)
	if err != nil {
		suite.Fail("Failed to validate refresh token")

	}
	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok {
		suite.Fail("Failed to find claim")
	}
	tokenId, ok := claims["token_id"].(string)

	if !ok {
		suite.Fail("Failed to find claim")

	}

	tokenResponse, err := suite.TokenRepository.GetTokenById(tokenId)
	if err != nil {
		suite.Fail("Failed to get token")
	}

	suite.Equal(tokenResponse.UserID, user.UserID)
	suite.Equal(tokenResponse.RefreshToken, response.RefreshToken)

	suite.Equal(response.Email, user.Email)
	suite.Equal(response.FullName, user.FullName)
	suite.Equal(response.PhoneNumber, user.PhoneNumber)
	suite.Equal(response.IsVerified, user.IsVerified)
	suite.Equal(response.IsProviderSignIn, user.IsProviderSignIn)
	suite.Equal(response.Role, "user")
	suite.Equal(response.IsProviderSignIn, false)
	suite.Equal(response.IsVerified, true)
	suite.NotEmpty(response.AccessToken)
	suite.NotEmpty(response.RefreshToken)

}

//user does not exist
func (suite *UserAuthTest) TestLoginUser_NotExist() {
	_, err := suite.UserAuthCase.SignIn(&dto.UserLoginDTO{
		Email:    "jan@gmail.com",
		Password: "password",
	})
	suite.Equal(err.Error(),"User does not exist")
	suite.Equal(err.StatusCode, 404)
}

//wrong password
func (suite *UserAuthTest) TestLoginUser_WrongPassword() {
	password, err := suite.HashingService.HashPassword("password")
	if err != nil {
		suite.Fail("Failed to hash password")
	}
	user := models.User{
		FullName:          "Jane Doe",
		Email:            "jan@gmail.com",
		IsVerified:        true,
		IsProviderSignIn:  false,
		PhoneNumber:       "1234567890",
		Password:          password,
	}
	_,err  = suite.UserRepository.CreateUser(&user)
	if err != nil {
		suite.Fail("Failed to create user")
	}
	_, err = suite.UserAuthCase.SignIn(&dto.UserLoginDTO{
		Email:    user.Email,
		Password: "wrongpassword",
	})
	suite.Equal(err.Error(),"Invalid email or password")
	suite.Equal(err.StatusCode, 401)
}

//user is not verified
func (suite *UserAuthTest) TestLoginUser_NotVerified() {
	password, err := suite.HashingService.HashPassword("password")
	if err != nil {
		suite.Fail("Failed to hash password")
	}
	user := models.User{
		FullName:          "Jane Doe",
		Email:            "jan@gmail.com",
		IsVerified:        false,
		IsProviderSignIn:  false,
		PhoneNumber:       "1234567890",
		Password:          password,
	}
	_,err  = suite.UserRepository.CreateUser(&user)
	if err != nil {
		suite.Fail("Failed to create user")
	}
	_, err = suite.UserAuthCase.SignIn(&dto.UserLoginDTO{
		Email:    user.Email,
		Password: "password",
	})
	suite.Equal(err.Error(),"User is not verified")
	suite.Equal(err.StatusCode, 401)
}

//refresh token
func (suite *UserAuthTest) TestRefreshToken() {
	user := models.User{
		FullName:          "Jane Doe",
		Email:            "jan@gmail.com",
		IsVerified:        true,
		IsProviderSignIn:  false,
		PhoneNumber:       "1234567890",
	}
	_,err  := suite.UserRepository.CreateUser(&user)
	if err != nil {
		suite.Fail("Failed to create user")
	}
	response, err := suite.UserAuthCase.SignIn(&dto.UserLoginDTO{
		Email:    user.Email,
		Password: "password",
	})
	if err != nil {
		suite.Fail("Failed to login user")
	}
	refreshToken := response.RefreshToken
	newResponse, err := suite.UserAuthCase.RefreshToken(&dto.RefreshTokenDTO{
		RefreshToken: refreshToken,
	})
	if err != nil {
		suite.Fail("Failed to refresh token")
	}
	token ,err := suite.JwtService.ValidateRefreshToken(refreshToken)
	if err != nil {
		suite.Fail("Failed to validate refresh token")

	}
	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok {
		suite.Fail("Failed to find claim")
	}
	tokenId, ok := claims["token_id"].(string)

	if !ok {
		suite.Fail("Failed to find claim")

	}

	tokenResponse, err := suite.TokenRepository.GetTokenById(tokenId)
	if err != nil {
		suite.Fail("Failed to get token")
	}
	
	suite.Equal(tokenResponse.TokenID, tokenId)
	suite.Equal(tokenResponse.UserID, user.UserID)
	suite.Equal(tokenResponse.RefreshToken, refreshToken)

	

	suite.NotEmpty(newResponse.AccessToken)
	suite.NotEmpty(newResponse.RefreshToken)
}

func (suite *UserAuthTest) TestResetPassword() {
	Password, err := suite.HashingService.HashPassword("password")
	if err != nil {
		suite.Fail("Failed to hash password")
	}
	user := models.User{
		UserID: uuid.New(),
		FullName:          "Jane Doe",
		Email:            "jane@example.com",
		IsVerified:        true,
		IsProviderSignIn:  false,
		PhoneNumber:       "1234567890",
		Password: 		Password,
		Role: "user",
		ProfileImage: "profile.jpg",

	}
	PasswordResetToken, err := suite.JwtService.GeneratePasswordResetToken(&user)
	if err != nil {
		suite.Fail("Failed to generate password reset token")
	}
	user.PasswordResetToken = PasswordResetToken
	_,err  = suite.UserRepository.CreateUser(&user)
	if err != nil {
		suite.Fail("Failed to create user")
	}

	err = suite.UserAuthCase.ResetPassword("newpassword", PasswordResetToken)
	if err != nil {
		suite.Fail("Failed to reset password")
	}
	userResponse, err := suite.UserRepository.GetUserById(user.UserID.String())
	if err != nil {
		suite.Fail("Failed to get user")
	}
	suite.True(suite.HashingService.ComparePassword("newpassword", userResponse.Password))
	
}

// verify email
func (suite *UserAuthTest) TestVerifyEmail() {

	user := models.User{
		UserID: uuid.New(),
VerificationToken : "token",
		FullName:          "Jane Doe",
		Email:            "jan@gmail.com",
		IsVerified:        false,
		IsProviderSignIn:  false,
		PhoneNumber:       "1234567890",

	}

	VerificationToken, err := suite.JwtService.GenerateVerificationToken(&user)
	if err != nil {
		suite.Fail("Failed to generate verification token")
	}

	user.VerificationToken = VerificationToken
	_,err  = suite.UserRepository.CreateUser(&user)

	if err != nil {
		suite.Fail("Failed to create user")
	}

	err = suite.UserAuthCase.VerifyEmail(VerificationToken)
	if err != nil {
		suite.Fail("Failed to verify email")
	}
	userResponse, err := suite.UserRepository.GetUserById(user.UserID.String())

	if err != nil {
		suite.Fail("Failed to get user")
	}
	suite.True(userResponse.IsVerified)
}


//handle provider sign in
func (suite *UserAuthTest) TestProviderSignIn() {
	user := models.User{
		FullName:          "Jane Doe",
		Email:            "jan@gmail.com",
		IsVerified:        true,
		IsProviderSignIn:  true,
		ProfileImage: "profile.jpg",
	}

	response, err := suite.UserAuthCase.HandleProviderSignIn(&user)
	if err != nil {
		suite.Fail("Failed to handle provider sign in")
	}

	token ,err := suite.JwtService.ValidateRefreshToken(response.RefreshToken)
	if err != nil {
		suite.Fail("Failed to validate refresh token")

	}
	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok {
		suite.Fail("Failed to find claim")
	}
	tokenId, ok := claims["token_id"].(string)

	if !ok {
		suite.Fail("Failed to find claim")

	}

	tokenResponse, err := suite.TokenRepository.GetTokenById(tokenId)
	if err != nil {
		suite.Fail("Failed to get token")
	}
	userResponse, err := suite.UserRepository.GetUserByEmail(user.Email)

	if err != nil {
		suite.Fail("Failed to get user")
	}

	suite.Equal(tokenResponse.UserID, userResponse.UserID)
	suite.Equal(tokenResponse.RefreshToken, response.RefreshToken)

	suite.Equal(response.Email, userResponse.Email)
	suite.Equal(response.FullName, userResponse.FullName)
	suite.Equal(response.PhoneNumber, userResponse.PhoneNumber)
	suite.Equal(response.IsVerified, userResponse.IsVerified)
	suite.Equal(response.IsProviderSignIn, userResponse.IsProviderSignIn)
	suite.Equal(response.Role, "user")
	suite.Equal(response.IsProviderSignIn, true)
	suite.Equal(response.IsVerified, true)
	suite.Equal(response.ProfileImage, userResponse.ProfileImage)

}

// handle provider sign in user already exists
func (suite *UserAuthTest) TestProviderSignIn_Exists() {
	Password, err := suite.HashingService.HashPassword("password")
	if err != nil {
		suite.Fail("Failed to hash password")
	}
	user := models.User{
		UserID: uuid.New(),
		FullName:          "Jane Doe",
		Email:            "jan@gmail.com",
		IsVerified:        false,
		IsProviderSignIn:  false,
		ProfileImage: "profile.jpg",
		Password: Password,
	}
	_,err  = suite.UserRepository.CreateUser(&user)
	if err != nil {
		suite.Fail("Failed to create user")
	}
	response, err := suite.UserAuthCase.HandleProviderSignIn(&user)
	if err != nil {
		suite.Fail("Failed to handle provider sign in")
	}

	suite.Equal(response.Email, user.Email)
	suite.Equal(response.FullName, user.FullName)
	suite.Equal(response.PhoneNumber, user.PhoneNumber)
	suite.Equal(response.IsProviderSignIn, user.IsProviderSignIn)
	suite.Equal(response.Role, "user")
	suite.Equal(response.IsVerified, true)
	suite.Equal(response.ProfileImage, user.ProfileImage)
	suite.NotEmpty(response.AccessToken)
	suite.NotEmpty(response.RefreshToken)
}


// sign out user
func (suite *UserAuthTest) TestSignOut() {
	Password, err := suite.HashingService.HashPassword("password")
	if err != nil {
		suite.Fail("Failed to hash password")
	}
	user := models.User{
		FullName:          "Jane Doe",
		Email:            "jane@gmail.com",
		IsVerified:        true,
		IsProviderSignIn:  false,
		PhoneNumber:       "1234567890",
		Password: Password,
		UserID: uuid.New(),
	}
	_,err  = suite.UserRepository.CreateUser(&user)
	if err != nil {
		suite.Fail("Failed to create user")
	}
	response, err := suite.UserAuthCase.SignIn(&dto.UserLoginDTO{
		Email:    user.Email,
		Password: "password",
	})
	if err != nil {
		suite.Fail("Failed to login user")
	}
	err = suite.UserAuthCase.SignOut(response.RefreshToken)
	if err != nil {
		suite.Fail("Failed to sign out user")
	}
	token ,err := suite.JwtService.ValidateRefreshToken(response.RefreshToken)
	if err != nil {
		suite.Fail("Failed to validate refresh token")

	}
	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok {
		suite.Fail("Failed to find claim")
	}
	tokenId, ok := claims["token_id"].(string)

	if !ok {
		suite.Fail("Failed to find claim")

	}

	_, err = suite.TokenRepository.GetTokenById(tokenId)


	suite.Equal(err.Error(),"token not found")
	suite.Equal(err.StatusCode, 404)
}



func TestUserUseAuthTestSuite(t *testing.T) {
	suite.Run(t, new(UserUseCaseTestSuite))
}
