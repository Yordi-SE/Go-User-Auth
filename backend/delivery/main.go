package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"user_authorization/delivery/controllers"
	"user_authorization/delivery/router"
	"user_authorization/infrastructure"
	"user_authorization/repositories"
	"user_authorization/usecases"

	"github.com/cloudinary/cloudinary-go"
	_ "github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/google"
	"gorm.io/driver/mysql"

	models "user_authorization/domain"

	gomail "gopkg.in/mail.v2"
	"gorm.io/gorm"
)

func main() {
	// Load .env file
	err := godotenv.Load("/app/.env")
	if err != nil {
		log.Fatal("Error loading .env file",err)
	}
	fmt.Println(os.Getenv("DB_CONNECTION_STRING"))
    db, err := gorm.Open(mysql.Open(os.Getenv("DB_CONNECTION_STRING")), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database", err)
	}

	err = db.AutoMigrate(&models.Token{})

	if err != nil {
		log.Fatal("Failed to connect to database", err)

	}
    err = db.AutoMigrate(&models.User{})
	if err != nil {
		log.Fatal("Failed to connect to database", err)

	}

	fmt.Println("Successfully connected to database")
	GMAIL_SMPT := os.Getenv("GMAIL_SMPT")
	GMAIL_USER_EMAIL := os.Getenv("GMAIL_USER_EMAIL")
	GMAIL_USER_PASSWORD := os.Getenv("GMAIL_USER_PASSWORD")
	EMAIL_PORT := os.Getenv("EMAIL_PORT")
	emailPort,err := strconv.Atoi(EMAIL_PORT)
	if err != nil {
		log.Fatal("Email port must be an integer")
	}
    dialer := gomail.NewDialer(GMAIL_SMPT, emailPort, GMAIL_USER_EMAIL, GMAIL_USER_PASSWORD)
	emailService := infrastructure.NewEmailService(dialer)

	GOOGLE_CLIENT_ID := os.Getenv("GOOGLE_CLIENT_ID")
	GOOGLE_CLIENT_SECRET := os.Getenv("GOOGLE_CLIENT_SECRET")
	GOOGlE_REDIRECT_URL := os.Getenv("GOOGLE_REDIRECT_URL")

	if GOOGLE_CLIENT_ID == "" || GOOGLE_CLIENT_SECRET == "" || GOOGlE_REDIRECT_URL == "" {
		log.Fatal("Google client id, client secret and redirect url must be set")
	}
	goth.UseProviders(
		google.New(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGlE_REDIRECT_URL,"profile","email"),
	)
	CLOUDINARY_API_KEY := os.Getenv("CLOUDINARY_API_KEY")
	CLOUDINARY_API_SECRET := os.Getenv("CLOUDINARY_API_SECRET")
	CLOUDINARY_CLOUD_NAME := os.Getenv("CLOUDINARY_CLOUD_NAME")

	cloudinary_url := fmt.Sprintf("cloudinary://%s:%s@%s",CLOUDINARY_API_KEY,CLOUDINARY_API_SECRET,CLOUDINARY_CLOUD_NAME)
	cld, err := cloudinary.NewFromURL(cloudinary_url)

	if err != nil {
		log.Fatal("Failed to connect to cloudinary", err)
	}

	fileUploadManager := infrastructure.NewFileUploadManager(cld)
	jwtService := infrastructure.NewJWTManager(os.Getenv("ACCESS_SECRET"), os.Getenv("REFRESH_SECRET"), os.Getenv("VERIFICATION_SECRET"),os.Getenv("PASSWORD_RESET_TOKEN"), os.Getenv("OTP_SECRET"))
	pwdService := infrastructure.NewHashingService()
	TokenRepo := repositories.NewTokenRepository(db)
	UserRepo := repositories.NewUserRepository(db)
	UserUsecase := usecases.NewUserUsecase(UserRepo, jwtService, pwdService, fileUploadManager,TokenRepo)
	userControllers := controllers.NewUserController(UserUsecase)
	UserAuth := usecases.NewUserAuth(UserRepo,pwdService,jwtService, emailService,TokenRepo, os.Getenv("TWO_FACTOR_SECRET"))
	userAuthController := controllers.NewUserAuthController(UserAuth,UserUsecase)
	routerService := router.RouterService{
		JwtService: jwtService,
	}
	routerControllers := router.RouterControllers{
		UserController: userControllers,
		UserAuthController: userAuthController,
	}
	router.NewRouter( &routerControllers, &routerService)

}

