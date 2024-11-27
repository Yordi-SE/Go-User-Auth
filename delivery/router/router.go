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
	

	router.LoadHTMLFiles("templates/verification_success.html", "templates/verification_fail.html")

	jwtService := routerService.JwtService

	router.POST("/user/register",routerControllers.UserAuthController.RegisterUser)
	router.GET("/user/get",infrastructure.AuthMiddleware(jwtService),routerControllers.UserAuthController.CheckToken,infrastructure.AdminAuthMiddleware(jwtService),routerControllers.UserController.GetUsers)
	router.GET("/user/get/:id",infrastructure.AuthMiddleware(jwtService),routerControllers.UserAuthController.CheckToken,infrastructure.UserAuthMiddleware(jwtService),routerControllers.UserAuthController.CheckToken,routerControllers.UserController.GetUserById)
	router.PUT("/user/update/:id",infrastructure.AuthMiddleware(jwtService),routerControllers.UserAuthController.CheckToken,infrastructure.UserAuthMiddleware(jwtService),routerControllers.UserController.UpdateUser)
	router.DELETE("/user/delete/:id",infrastructure.AuthMiddleware(jwtService),routerControllers.UserAuthController.CheckToken,infrastructure.UserAuthMiddleware(jwtService),routerControllers.UserController.DeleteUser)
	router.POST("/user/upload/:id",infrastructure.AuthMiddleware(jwtService),routerControllers.UserAuthController.CheckToken,infrastructure.UserAuthMiddleware(jwtService),routerControllers.UserController.UploadProfileImagefunc)
	router.POST("/user/login",routerControllers.UserAuthController.Login)
	router.GET("/user/logout",infrastructure.AuthMiddleware(jwtService),routerControllers.UserAuthController.Logout)
	router.GET("/user/:provider",routerControllers.UserAuthController.SignInWithProvider)
	router.GET("/api/auth/:provider/callback",routerControllers.UserAuthController.Callback)
	router.POST("/user/refresh",routerControllers.UserAuthController.RefreshToken)
	router.GET("/user/verify_email",routerControllers.UserAuthController.VerifyEmail)
	router.Run(":" + os.Getenv("PORT"))
}

