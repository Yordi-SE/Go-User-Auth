package main

import (
	"fmt"
	"log"
	"os"
	"user_authorization/delivery/controllers"
	"user_authorization/delivery/router"
	"user_authorization/infrastructure"
	"user_authorization/repositories"
	"user_authorization/usecases"

	_ "github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
	"gorm.io/driver/mysql"

	models "user_authorization/domain"

	"gorm.io/gorm"
)

func main() {
	// Load .env file
	err := godotenv.Load("../.env")
	if err != nil {
		log.Fatal("Error loading .env file",err)
	}
	fmt.Println(os.Getenv("DB_CONNECTION_STRING"))
    db, err := gorm.Open(mysql.Open(os.Getenv("DB_CONNECTION_STRING")), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database", err)
	}

    db.AutoMigrate(&models.User{})

	fmt.Println("Successfully connected to database")
	jwtService := infrastructure.NewJWTManager(os.Getenv("ACCESS_SECRET"), os.Getenv("REFRESH_SECRET"))
	pwdService := infrastructure.NewHashingService()
	UserRepo := repositories.NewUserRepository(db)
	UserUsecase := usecases.NewUserUsecase(UserRepo, jwtService, pwdService)
	userControllers := controllers.NewUserController(UserUsecase)
	UserAuth := usecases.NewUserAuth(UserRepo,pwdService,jwtService)
	userAuthController := controllers.NewUserAuthController(UserAuth)
	routerService := router.RouterService{
		JwtService: jwtService,
	}
	routerControllers := router.RouterControllers{
		UserController: userControllers,
		UserAuthController: userAuthController,
	}
	router.NewRouter( &routerControllers, &routerService)

}

