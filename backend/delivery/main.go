package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"github.com/markbates/goth/gothic"
	"strconv"
	"github.com/gorilla/sessions"
	"user_authorization/delivery/controllers"
	"user_authorization/delivery/router"
	"user_authorization/infrastructure"
	"user_authorization/repositories"
	"user_authorization/usecases"

	"github.com/redis/go-redis/v9"

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
    db, err := gorm.Open(mysql.Open(os.Getenv("DB_CONNECTION_STRING")), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database", err)
	}
    err = db.AutoMigrate(&models.User{})
	if err != nil {
		log.Fatal("Failed to connect to database", err)

	}

	redisClient := redis.NewClient(&redis.Options{
		Addr:     "redis:6379",
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       0,
		Protocol: 2,
	})
	_, err = redisClient.Ping(context.Background()).Result()
	if err != nil {
		log.Fatal(err)
	}
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
	gothic_secret_key := os.Getenv("SESSION_SECRET") // Replace with a strong, unique key
	store := sessions.NewCookieStore([]byte(gothic_secret_key))
	store.MaxAge(86400 * 30) // Sessions last 30 days
	store.Options.Path = "/"
	store.Options.HttpOnly = true // Prevents JavaScript access to cookies
	store.Options.Secure = false  // Set to true in production with HTTPS

	// Assign the store to gothic
	gothic.Store = store
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
	cacheRepo := infrastructure.NewCacheRepo(redisClient, context.Background())

	fileUploadManager := infrastructure.NewFileUploadManager(cld)
	jwtService := infrastructure.NewJWTManager(os.Getenv("ACCESS_SECRET"), os.Getenv("REFRESH_SECRET"), os.Getenv("VERIFICATION_SECRET"),os.Getenv("PASSWORD_RESET_TOKEN"), os.Getenv("OTP_SECRET"),os.Getenv("PROVIDERTOKENSECRET"))
	pwdService := infrastructure.NewHashingService()
	UserRepo := repositories.NewUserRepository(db)
	UserUsecase := usecases.NewUserUsecase(UserRepo, jwtService, pwdService, fileUploadManager,cacheRepo)
	userControllers := controllers.NewUserController(UserUsecase)
	UserAuth := usecases.NewUserAuth(UserRepo,pwdService,jwtService, emailService, os.Getenv("TWO_FACTOR_SECRET"),cacheRepo)
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

