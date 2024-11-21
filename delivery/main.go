package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"user_authorization/delivery/controllers"
	"user_authorization/delivery/router"
	"user_authorization/repositories"
	"user_authorization/usecases"

	_ "github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
)

func main() {
	// Load .env file
	err := godotenv.Load("../.env")
	if err != nil {
		log.Fatal("Error loading .env file",err)
	}
	fmt.Println(os.Getenv("DB_CONNECTION_STRING"))
	db, err := sql.Open("mysql", os.Getenv("DB_CONNECTION_STRING"))
	if err != nil {
		fmt.Println(err)
	}
	defer db.Close()
	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Successfully connected to database")
	UserRepo := repositories.NewUserRepository(db)
	UserUsecase := usecases.NewUserUsecase(UserRepo)
	userControllers := controllers.NewUserController(UserUsecase)
	routerControllers := router.RouterControllers{
		UserController: userControllers,
	}
	router.NewRouter( &routerControllers)

}

