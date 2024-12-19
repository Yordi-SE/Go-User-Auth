package usecase_test

import (
	"context"
	"fmt"
	"log"
	"mime/multipart"
	"os"
	"strings"
	"testing"
	models "user_authorization/domain"
	"user_authorization/infrastructure"
	"user_authorization/repositories"
	"user_authorization/test/mocks"
	"user_authorization/usecases"
	"user_authorization/usecases/dto"

	"github.com/redis/go-redis/v9"

	"github.com/joho/godotenv"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)




type UserUseCaseTestSuite struct {
	suite.Suite
	UserUsecase *usecases.UserUsecase
	UserAuthCase *usecases.UserAuth
	UserRepository *repositories.UserRepository
	
	JwtService *infrastructure.JWTManager
	HashingService *infrastructure.HashingService
	MockFileUploadManager *mocks.FileUploadManagerI
	MockEmailService *mocks.EmailServiceI
	cacheRepo *infrastructure.CacheRepo
	DB *gorm.DB
}

func (suite *UserUseCaseTestSuite) SetupTest() {
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
	suite.cacheRepo = infrastructure.NewCacheRepo(redisClient,context.Background())
	suite.JwtService = infrastructure.NewJWTManager(os.Getenv("ACCESS_SECRET"), os.Getenv("REFRESH_SECRET"), os.Getenv("VERIFICATION_SECRET"),os.Getenv("PASSWORD_RESET_TOKEN"),os.Getenv("OTP_SECRET"),os.Getenv("PROVIDERTOKENSECRET"))
	suite.HashingService = infrastructure.NewHashingService()
	suite.MockFileUploadManager = new(mocks.FileUploadManagerI)
	suite.MockEmailService = new(mocks.EmailServiceI)
	suite.UserRepository = repositories.NewUserRepository(db)
	suite.UserUsecase = usecases.NewUserUsecase(suite.UserRepository, suite.JwtService, suite.HashingService, suite.MockFileUploadManager, suite.cacheRepo)
	suite.UserAuthCase = usecases.NewUserAuth(suite.UserRepository,  suite.HashingService, suite.JwtService, suite.MockEmailService,os.Getenv("TWO_FACTOR_SECRET"),suite.cacheRepo)
}


func (suite *UserUseCaseTestSuite) TearDownTest() {
	if err := suite.DB.Exec("TRUNCATE TABLE users").Error; err != nil {
		suite.T().Fatal("Failed to truncate users table", err)
}
}




func (suite *UserUseCaseTestSuite) TestGetUser() {

    // Insert a user into the in-memory database.
    user := models.User{
        FullName:          "Jane Doe",
        Email:             "jane@example.com",
        IsVerified:        false,
        IsProviderSignIn:  false,
        PhoneNumber:       "1234567890",

    }
    
	
    // Assuming you have a method to insert this user into the test database.
    suite.MockEmailService.On(
        "GetOTPEmailBody",
        mock.MatchedBy(func(arg string) bool {
            return strings.HasPrefix(arg, "localhost:8080") 
        }),
        mock.MatchedBy(func(arg string) bool {
            return arg == "email_verification.html" 
        }),
    ).Return("email body", nil) // Return expected email body

    suite.MockEmailService.On(
        "SendEmail",
        user.Email,          
        "Email Verification", 
        "email body",        
        "go_auth@gmail.com", 
    ).Return(nil)

	_,err := suite.UserAuthCase.CreateUser(&dto.UserRegistrationDTO{
		FullName:    user.FullName,
		Email:       user.Email,
		Password:    user.Password,
		PhoneNumber: user.PhoneNumber,
	})

	if err != nil {	
		suite.Fail("Failed to create user")
	}
	// Define the expected response.


	expectedResponse := dto.UserResponseDTO{
        FullName:        user.FullName,
        Email:           user.Email,
        PhoneNumber:     user.PhoneNumber,
        IsProviderSignIn: user.IsProviderSignIn,
        IsVerified:      user.IsVerified,

    }

    // Call the method being tested.
	response, err := suite.UserUsecase.GetUsers(1)
	if err != nil {
		suite.Fail("Failed to get users")
	}

 


	suite.Equal(len(response), 1)
	

	actualResponse := response[0] 
    suite.Equal(expectedResponse.FullName, actualResponse.FullName)
    suite.Equal(expectedResponse.Email, actualResponse.Email)
    suite.Equal(expectedResponse.PhoneNumber, actualResponse.PhoneNumber)
    suite.Equal(expectedResponse.IsVerified, actualResponse.IsVerified)
    suite.Equal(expectedResponse.IsProviderSignIn, actualResponse.IsProviderSignIn)
    suite.Equal(actualResponse.Role, "user")
	suite.Equal("", actualResponse.ProfileImage)

	suite.Empty(actualResponse.RefreshToken, "RefreshToken should be empty")
    suite.Empty(actualResponse.AccessToken, "AccessToken should be empty")
	suite.NotEmpty(actualResponse.UserId, "UserId should not be empty")

    suite.MockEmailService.AssertExpectations(suite.T())
}

func (suite *UserUseCaseTestSuite) TestGetUserById() {

    user := models.User{
        FullName:          "Jane Doe",
        Email:             "jane@example.com",
        Password:          "password",
        IsVerified:        false,
        IsProviderSignIn:  false,
        PhoneNumber:       "1234567890",
    }
    
	
    // Assuming you have a method to insert this user into the test database.
    suite.MockEmailService.On(
        "GetOTPEmailBody",
        mock.MatchedBy(func(arg string) bool {
            return strings.HasPrefix(arg, "localhost:8080") 
        }),
        mock.MatchedBy(func(arg string) bool {
            return arg == "email_verification.html" 
        }),
    ).Return("email body", nil) // Return expected email body

    suite.MockEmailService.On(
        "SendEmail",
        user.Email,          
        "Email Verification", 
        "email body",        
        "go_auth@gmail.com", 
    ).Return(nil)

	res,err := suite.UserAuthCase.CreateUser(&dto.UserRegistrationDTO{
		FullName:    user.FullName,
		Email:       user.Email,
		Password:    user.Password,
		PhoneNumber: user.PhoneNumber,
	})

	if err != nil {	
		suite.Fail("Failed to create user")
	}


	expectedResponse := dto.UserResponseDTO{
        FullName:        user.FullName,
        Email:           user.Email,
        PhoneNumber:     user.PhoneNumber,
        IsProviderSignIn: user.IsProviderSignIn,
        IsVerified:      user.IsVerified,
    }

    // Call the method being tested.
	response, err := suite.UserUsecase.GetUserById(res.UserId.String())
	if err != nil {
		suite.Fail("Failed to get users")
	}


    suite.Equal(expectedResponse.FullName, response.FullName)
    suite.Equal(expectedResponse.Email, response.Email)
    suite.Equal(expectedResponse.PhoneNumber, response.PhoneNumber)
    suite.Equal(expectedResponse.IsVerified, response.IsVerified)
    suite.Equal(expectedResponse.IsProviderSignIn, response.IsProviderSignIn)
    suite.Equal(response.Role, "user")
	suite.Equal("", response.ProfileImage)

	suite.Empty(response.RefreshToken, "RefreshToken should be empty")
    suite.Empty(response.AccessToken, "AccessToken should be empty")
	suite.NotEmpty(response.UserId, "UserId should not be empty")

    suite.MockEmailService.AssertExpectations(suite.T())
}


func (suite *UserUseCaseTestSuite) TestUpdateUser() {

    user := models.User{
        FullName:          "Jane Doe",
        Email:             "jane@example.com",
        Password:          "password",
        IsVerified:        false,
        IsProviderSignIn:  false,
        PhoneNumber:       "1234567890",
    }
    
	
    // Assuming you have a method to insert this user into the test database.
    suite.MockEmailService.On(
        "GetOTPEmailBody",
        mock.MatchedBy(func(arg string) bool {
            return strings.HasPrefix(arg, "localhost:8080") 
        }),
        mock.MatchedBy(func(arg string) bool {
            return arg == "email_verification.html" 
        }),
    ).Return("email body", nil) // Return expected email body

    suite.MockEmailService.On(
        "SendEmail",
        user.Email,          
        "Email Verification", 
        "email body",        
        "go_auth@gmail.com", 
    ).Return(nil)

	res,err := suite.UserAuthCase.CreateUser(&dto.UserRegistrationDTO{
		FullName:    user.FullName,
		Email:       user.Email,
		Password:    user.Password,
		PhoneNumber: user.PhoneNumber,
	})

	if err != nil {	
		suite.Fail("Failed to create user")
	}


	expectedResponse := dto.UserResponseDTO{
        Email:           user.Email,
        IsProviderSignIn: user.IsProviderSignIn,
        IsVerified:      user.IsVerified,
    }

    // Call the method being tested.
	 err = suite.UserUsecase.UpdateUser(res.UserId.String(), &dto.UserUpdateDTO{
		FullName: "Yordanos Lemmawork",
		PhoneNumber: "0987654321",
		ProfileImage: "profile.jpg",

	})

	if err != nil {
		suite.Fail("Failed to get users")
	}

    response, err := suite.UserUsecase.GetUserById(res.UserId.String())

	if err != nil {
		suite.Fail("Failed to get users")
	}


    suite.Equal(response.FullName, "Yordanos Lemmawork")
    suite.Equal(expectedResponse.Email, response.Email)
    suite.Equal(response.PhoneNumber, "0987654321")
    suite.Equal(expectedResponse.IsVerified, response.IsVerified)
    suite.Equal(expectedResponse.IsProviderSignIn, response.IsProviderSignIn)
    suite.Equal(response.Role, "user")
	suite.Equal("profile.jpg", response.ProfileImage)

	suite.Empty(response.RefreshToken, "RefreshToken should be empty")
    suite.Empty(response.AccessToken, "AccessToken should be empty")
	suite.NotEmpty(response.UserId, "UserId should not be empty")

    suite.MockEmailService.AssertExpectations(suite.T())
}



func (suite *UserUseCaseTestSuite) TestDeleteUser() {

    user := models.User{
        FullName:          "Jane Doe",
        Email:             "jane@example.com",
        Password:          "password",
        PhoneNumber:       "1234567890",
    }
    
	
    // Assuming you have a method to insert this user into the test database.
    suite.MockEmailService.On(
        "GetOTPEmailBody",
        mock.MatchedBy(func(arg string) bool {
            return strings.HasPrefix(arg, "localhost:8080") 
        }),
        mock.MatchedBy(func(arg string) bool {
            return arg == "email_verification.html" 
        }),
    ).Return("email body", nil) // Return expected email body

    suite.MockEmailService.On(
        "SendEmail",
        user.Email,          
        "Email Verification", 
        "email body",        
        "go_auth@gmail.com", 
    ).Return(nil)

	res,err := suite.UserAuthCase.CreateUser(&dto.UserRegistrationDTO{
		FullName:    user.FullName,
		Email:       user.Email,
		Password:    user.Password,
		PhoneNumber: user.PhoneNumber,
	})

	if err != nil {	
		suite.Fail("Failed to create user")
	}

	 err = suite.UserUsecase.DeleteUser(res.UserId.String())

	if err != nil {
		suite.Fail("Failed to get users")
	}

    _, err = suite.UserUsecase.GetUserById(res.UserId.String())

    suite.NotNil(err)
    suite.Equal(err.Message, "user not found")
    suite.Equal(err.StatusCode, 404)

    suite.MockEmailService.AssertExpectations(suite.T())
}



func (suite *UserUseCaseTestSuite) TestUploadProfilePic() {

    user := models.User{
        FullName:          "Jane Doe",
        Email:             "jane@example.com",
        Password:          "password",
        PhoneNumber:       "1234567890",
    }
    
    fileContents := []byte("this is a test file")

	// Create a *multipart.FileHeader
	fileHeader := &multipart.FileHeader{
		Filename: "testfile.txt",
		Size:     int64(len(fileContents)),
		Header:   make(map[string][]string),
	}

	
    suite.MockEmailService.On(
        "GetOTPEmailBody",
        mock.MatchedBy(func(arg string) bool {
            return strings.HasPrefix(arg, "localhost:8080") 
        }),
        mock.MatchedBy(func(arg string) bool {
            return arg == "email_verification.html" 
        }),
    ).Return("email body", nil) // Return expected email body

    suite.MockEmailService.On(
        "SendEmail",
        user.Email,          
        "Email Verification", 
        "email body",        
        "go_auth@gmail.com", 
    ).Return(nil)

	res,err := suite.UserAuthCase.CreateUser(&dto.UserRegistrationDTO{
		FullName:    user.FullName,
		Email:       user.Email,
		Password:    user.Password,
		PhoneNumber: user.PhoneNumber,
	})

	if err != nil {	
		suite.Fail("Failed to create user")
	}
    suite.MockFileUploadManager.On("UploadFile",res.UserId.String(),fileHeader).Return("https://cloudinary.com/testfile.txt", nil)
    
	secureUrl,err := suite.UserUsecase.UploadProfilePic(res.UserId.String(),fileHeader)

	if err != nil {
		suite.Fail("Failed to get users")
	}

    response, err := suite.UserUsecase.GetUserById(res.UserId.String())
	if err != nil {
		suite.Fail("Failed to get users")
	}
    suite.Equal(secureUrl, "https://cloudinary.com/testfile.txt")
    suite.Equal(response.ProfileImage, "https://cloudinary.com/testfile.txt")
    suite.MockEmailService.AssertExpectations(suite.T())
    suite.MockFileUploadManager.AssertExpectations(suite.T())
}

// Run the test suite
func TestUserUseCaseTestSuite(t *testing.T) {
	suite.Run(t, new(UserUseCaseTestSuite))
}
