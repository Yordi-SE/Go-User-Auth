package usecase_test

import (
	"context"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
	models "user_authorization/domain"
	"user_authorization/infrastructure"
	"user_authorization/repositories"
	"user_authorization/test/mocks"
	"user_authorization/usecases"
	"user_authorization/usecases/dto"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"

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
	MockEmailService      *mocks.EmailServiceI
	UserUsecase *usecases.UserUsecase
	UserAuthCase *usecases.UserAuth
	cacheRepo *infrastructure.CacheRepo
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
	redisClient := redis.NewClient(&redis.Options{
        Addr:	  "localhost:6379",
        Password: "", // No password set
        DB:		  0,  // Use default DB
        Protocol: 2,  // Connection protocol
    })
	ctx := context.Background()

	err = redisClient.Set(ctx, "foo", "bar", 0).Err()
	if err != nil {
		panic(err)
	}

	val, err := redisClient.Get(ctx, "foo").Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("foo", val)
	suite.DB = db
	suite.JwtService = infrastructure.NewJWTManager(os.Getenv("ACCESS_SECRET"), os.Getenv("REFRESH_SECRET"), os.Getenv("VERIFICATION_SECRET"),os.Getenv("PASSWORD_RESET_TOKEN"),os.Getenv("OTP_SECRET"),os.Getenv("PROVIDERTOKENSECRET"))
	suite.HashingService = infrastructure.NewHashingService()
	suite.MockFileUploadManager = new(mocks.FileUploadManagerI)
	suite.MockEmailService = new(mocks.EmailServiceI)
	suite.cacheRepo = infrastructure.NewCacheRepo(redisClient,context.Background())
	suite.UserRepository = repositories.NewUserRepository(db)
	suite.UserUsecase = usecases.NewUserUsecase(suite.UserRepository, suite.JwtService, suite.HashingService, suite.MockFileUploadManager, suite.cacheRepo)
	suite.UserAuthCase = usecases.NewUserAuth(suite.UserRepository,  suite.HashingService, suite.JwtService, suite.MockEmailService, os.Getenv("TwO_FACTOR_SECRET"),suite.cacheRepo)
}

func (suite *UserAuthTest) TearDownTest() {
	if err := suite.DB.Exec("TRUNCATE TABLE users").Error; err != nil {
		suite.T().Fatal("Failed to truncate users table", err)
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
            return arg == "email_verification.html" 
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
		UserID: uuid.New(),
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

	tokenResponse, err := suite.cacheRepo.Get(user.UserID.String() + tokenId)
	if err != nil {
		suite.Fail("Failed to get token")
	}

	suite.Equal(tokenResponse, response.RefreshToken)

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
	suite.Equal(err.Error(),"user not found")
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
	suite.Equal(err.Error(),"Email address is not verified.")
	suite.Equal(err.StatusCode, 401)
}

//user 2fa enabled
func (suite *UserAuthTest) TestLoginUser_TwoFactorAuth() {
	password , errr := suite.HashingService.HashPassword("password")
	if errr != nil {
		suite.Fail("Failed to hash password")
	}
	user := models.User{
		FullName:          "Jane Doe",
		Email:            "jane@gmail.com",
		IsProviderSignIn: false,
		IsVerified: true,
		TwoFactorAuth: true,
		PhoneNumber:       "1234567890",
		Password: password,
	}
	_,err  := suite.UserRepository.CreateUser(&user)
	if err != nil {
		suite.Fail("Failed to create user")
	}
	otpRegex := regexp.MustCompile(`^\d{6}$`)

   suite.MockEmailService.On(
        "GetOTPEmailBody",
		mock.MatchedBy(func(arg string) bool {
			// Check if the OTP matches the 6-digit pattern
			return otpRegex.MatchString(arg)
		}),
        mock.MatchedBy(func(arg string) bool {
            return arg == "otp_verification.html" 
        }),
    ).Return("email body", nil)
    suite.MockEmailService.On(
        "SendEmail",
        user.Email,          
        "Two Factor Authentication", 
        "email body",        
        "go_auth@gmail.com", 
    ).Return(nil)
	token, err := suite.UserAuthCase.SignIn(&dto.UserLoginDTO{
		Email:    user.Email,
		Password: "password",
	})
	if err != nil {
		suite.Fail("Failed to login user")
	}
	suite.Equal(token.AccessToken,"")
	suite.Equal(token.RefreshToken,"")
	suite.Equal(token.Email, user.Email)
	suite.Equal(token.FullName, user.FullName)
	suite.Equal(token.PhoneNumber, user.PhoneNumber)
	suite.Equal(token.IsVerified, user.IsVerified)
	suite.Equal(token.IsProviderSignIn, user.IsProviderSignIn)
	suite.Equal(token.Role, "user")
	suite.Equal(token.IsProviderSignIn, false)
	suite.Equal(token.IsVerified, true)
	suite.Equal(token.TwoFactorAuth, true)
	

}

//refresh token
func (suite *UserAuthTest) TestRefreshToken() {
	Password, err := suite.HashingService.HashPassword("password")
	if err != nil {
		suite.Fail("Failed to hash password")
	}
	user := models.User{
		UserID: uuid.New(),
		FullName:          "Jane Doe",
		Email:            "jan@gmail.com",
		IsVerified:        true,
		IsProviderSignIn:  false,
		PhoneNumber:       "1234567890",
		Password: Password,
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
	//.Println(response)
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
	refreshToken := response.RefreshToken

	newResponse, err := suite.UserAuthCase.RefreshToken(&dto.RefreshTokenDTO{
		RefreshToken: refreshToken,
	})
	if err != nil {
		suite.Fail("Failed to refresh token")
	}


	tokenResponse, err := suite.cacheRepo.Get(user.UserID.String() + tokenId)
	if err != nil {
		suite.Fail("Failed to get token")
	}
	
	suite.Equal(tokenResponse, refreshToken)

	

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
	_,err  = suite.UserRepository.CreateUser(&user)
	if err != nil {
		suite.Fail("Failed to create user")
	}
	err = suite.cacheRepo.Set(user.Email + "password_reset_token",PasswordResetToken, time.Minute * 30)
	err = suite.UserAuthCase.ResetPassword("newpassword", PasswordResetToken)
	if err != nil {
		suite.Fail("Failed to reset password",err)
	}
	userResponse, err := suite.UserRepository.GetUserById(user.UserID.String())
	if err != nil {
		suite.Fail("Failed to get user")
	}
	//.Println(userResponse)
	suite.True(suite.HashingService.ComparePassword(userResponse.Password,"newpassword"))
	
}

// verify email
func (suite *UserAuthTest) TestVerifyEmail() {

	user := models.User{
		UserID: uuid.New(),
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

	err = suite.cacheRepo.Set(user.Email + "verification_token",VerificationToken, time.Minute * 30)
	if err != nil {
		suite.Fail("Failed to set cache")
	}
	_,err  = suite.UserRepository.CreateUser(&user)

	if err != nil {
		suite.Fail("Failed to create user")
	}

	err = suite.UserAuthCase.VerifyEmail(VerificationToken)
	if err != nil {
		suite.Fail("Failed to verify email",err)
	}
	userResponse, err := suite.UserRepository.GetUserById(user.UserID.String())

	if err != nil {
		suite.Fail("Failed to get user")
	}
	fmt.Println(userResponse.IsVerified, "is verified")
	suite.True(userResponse.IsVerified)
}


//handle provider sign in




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
	err = suite.UserAuthCase.SignOut(tokenId, user.UserID.String())
	if err != nil {
		suite.Fail("Failed to sign out user")
	}

	_, err = suite.cacheRepo.Get(user.UpdatedAt.String() + tokenId)


	suite.Equal(err.Error(),"error getting cache")
	suite.Equal(err.StatusCode, 500)
}

//handle provider sign in
func (suite *UserAuthTest) TestHandleProviderSignIn() {
	user := models.User{
		UserID: uuid.New(),
		FullName:          "Jane Doe",
		Email:            "Jane@gmail.com",
		IsVerified:        false,
		IsProviderSignIn:  false,
		PhoneNumber:       "1234567890",
	}
	_,err  := suite.UserRepository.CreateUser(&user)
	if err != nil {
		suite.Fail("Failed to create user")
	}
	result,err := suite.UserAuthCase.HandleProviderSignIn(&user)

	if err != nil {
		suite.Fail("Failed to handle provider sign in")
	}

	tokenstring, err := suite.JwtService.ValidateProviderToken(result)
	if err != nil {
		suite.Fail("Failed to validate provider token")
	}
	claims, ok := tokenstring.Claims.(jwt.MapClaims)

	if !ok {
		suite.Fail("Failed to find claim")
	}
	user_email, ok := claims["user_email"].(string)

	if !ok {
		suite.Fail("Failed to find claim")

	}
	tokenResult,err := suite.cacheRepo.Get(user.Email+"provider_token")
	if err != nil {
		suite.Fail("Failed to get token")
	}

	suite.Equal(tokenResult, result)
	suite.Equal(user_email, user.Email)

}

//provider sign in new user
func (suite *UserAuthTest) TestProviderSignInNewUser() {
	user := models.User{
		UserID: uuid.New(),
		FullName:          "Jane Doe",
		Email:            "Jane@gmail.com",
		IsVerified:        true,
		Role: "user",
		IsProviderSignIn:  true,
		PhoneNumber:       "1234567890",
	}
	result, err := suite.UserAuthCase.HandleProviderSignIn(&user)
	if err != nil {
		suite.Fail("Failed to handle provider sign in")
	}

	tokenstring, err := suite.JwtService.ValidateProviderToken(result)
	if err != nil {
		suite.Fail("Failed to validate provider token")
	}
	claims, ok := tokenstring.Claims.(jwt.MapClaims)

	if !ok {
		suite.Fail("Failed to find claim")
	}
	user_email, ok := claims["user_email"].(string)

	if !ok {
		suite.Fail("Failed to find claim")

	}
	tokenResult,err := suite.cacheRepo.Get(user.Email+"provider_token")
	if err != nil {
		suite.Fail("Failed to get token")
	}
	response, err := suite.UserRepository.GetUserByEmail(user_email)
	if err != nil {
		suite.Fail("Failed to get user")
	}
	suite.Equal(tokenResult, result)
	suite.Equal(user_email, user.Email)
	suite.Equal(response.Email, user_email)
	suite.Equal(response.FullName, user.FullName)
	suite.Equal(response.PhoneNumber, user.PhoneNumber)
	suite.Equal(response.IsVerified, user.IsVerified)
	suite.Equal(response.IsProviderSignIn, user.IsProviderSignIn)
	suite.Equal(response.Role, "user")
	suite.Equal(response.IsProviderSignIn, true)
	suite.Equal(response.IsVerified, true)


}

// two factor auth
func (suite *UserAuthTest) TestTwoFactorAuth() {
	user := models.User{
		FullName:          "Jane Doe",
		Email:            "jane@gmail.com",
		IsVerified:        true,
		IsProviderSignIn:  false,
		PhoneNumber:       "1234567890",
		TwoFactorAuth: true,
	}
	_,err  := suite.UserRepository.CreateUser(&user)
	if err != nil {
		suite.Fail("Failed to create user")
	}
	otp_token, errr := suite.JwtService.GenerateOtpToken(&user)
	if errr != nil {
		suite.Fail("Failed to generate otp token")
	}
	SecretKey := suite.UserAuthCase.TwoFactorSecretKey
	otpCode, errs := totp.GenerateCode(SecretKey, time.Now())
	if errs != nil {
		suite.Fail("Failed to generate otp code")
	}
	err = suite.cacheRepo.Set(user.Email + "otp_token",otp_token, time.Minute * 30)
	if err != nil {
		suite.Fail("Failed to set cache")
	}
	err = suite.cacheRepo.Set(user.Email + "otp_code",otpCode, time.Minute * 30)
	token, err := suite.UserAuthCase.TwoFactorAuthenticationVerification(user.Email,otpCode,otp_token)
	if err != nil {
		suite.Fail("Failed to verify otp code")
	}
	suite.NotEmpty(token.AccessToken)
	suite.NotEmpty(token.RefreshToken)
	suite.Equal(token.Email, user.Email)
	suite.Equal(token.FullName, user.FullName)
	suite.Equal(token.PhoneNumber, user.PhoneNumber)
	suite.Equal(token.IsVerified, user.IsVerified)
	suite.Equal(token.IsProviderSignIn, user.IsProviderSignIn)
	suite.Equal(token.Role, "user")
	suite.Equal(token.IsProviderSignIn, false)
	suite.Equal(token.IsVerified, true)
	suite.Equal(token.TwoFactorAuth, true)

}

func TestUserUseAuthTestSuite(t *testing.T) {
	suite.Run(t, new(UserAuthTest))
}
