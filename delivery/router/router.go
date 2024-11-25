package router

import (
	"os"
	"user_authorization/delivery/controllers"
	"user_authorization/infrastructure"

	"github.com/gin-gonic/gin"
)

type RouterControllers struct {
	UserController *controllers.UserController
	UserAuthController *controllers.UserAuthController
}

type RouterService struct {
	JwtService *infrastructure.JWTManager

}

func NewRouter ( routerControllers *RouterControllers, routerService *RouterService)  {
	router := gin.Default()

	jwtService := routerService.JwtService

	router.POST("/user/register",routerControllers.UserController.RegisterUser)
	router.GET("/user/get",infrastructure.AuthMiddleware(jwtService),routerControllers.UserAuthController.CheckToken,infrastructure.AdminAuthMiddleware(jwtService),routerControllers.UserController.GetUsers)
	router.GET("/user/get/:id",infrastructure.AuthMiddleware(jwtService),routerControllers.UserAuthController.CheckToken,infrastructure.UserAuthMiddleware(jwtService),routerControllers.UserAuthController.CheckToken,routerControllers.UserController.GetUserById)
	router.PUT("/user/update/:id",infrastructure.AuthMiddleware(jwtService),routerControllers.UserAuthController.CheckToken,infrastructure.UserAuthMiddleware(jwtService),routerControllers.UserController.UpdateUser)
	router.DELETE("/user/delete/:id",infrastructure.AuthMiddleware(jwtService),routerControllers.UserAuthController.CheckToken,infrastructure.UserAuthMiddleware(jwtService),routerControllers.UserController.DeleteUser)
	router.POST("/user/login",routerControllers.UserAuthController.Login)
	router.GET("/user/logout",infrastructure.AuthMiddleware(jwtService),routerControllers.UserAuthController.Logout)
	router.POST("/user/refresh",routerControllers.UserAuthController.RefreshToken)
	router.Run(":" + os.Getenv("PORT"))
}

