package router

import (
	"os"
	"time"
	"user_authorization/delivery/controllers"
	"user_authorization/infrastructure"

	"github.com/gin-contrib/cors"

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
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"http://localhost:3000"}
	config.AllowCredentials = true
	config.AllowMethods = []string{"GET", "POST", "PUT", "DELETE","OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Content-Length", "Content-Type", "Authorization","access-control-allow-origin","access-control-allow-headers","access-control-allow-methods","access-control-allow-credentials","Accept", "User-Agent", "Cache-Control"}
	config.ExposeHeaders = []string{"Content-Length"}
	config.MaxAge = 12 * time.Hour
	router.Use(cors.New(config))
	router.LoadHTMLFiles("templates/verification_success.html", "templates/verification_fail.html")

	jwtService := routerService.JwtService

	userGroup := router.Group("/api/user")
	userGroup.Use(infrastructure.RateLimitMiddleware())
	userGroup.Use(infrastructure.AuthMiddleware(jwtService))

	userGroup.Use(routerControllers.UserAuthController.CheckToken)

	userGroup.GET("/get",infrastructure.AdminAuthMiddleware(jwtService),routerControllers.UserController.GetUsers)
	userGroup.GET("/get/:id",infrastructure.UserAuthMiddleware(jwtService),routerControllers.UserAuthController.CheckToken,routerControllers.UserController.GetUserById)
	userGroup.PUT("/update/:id",infrastructure.UserAuthMiddleware(jwtService),routerControllers.UserController.UpdateUser)
	userGroup.DELETE("/delete/:id",infrastructure.UserAuthMiddleware(jwtService),routerControllers.UserController.DeleteUser)
	userGroup.POST("/upload/:id",infrastructure.UserAuthMiddleware(jwtService),routerControllers.UserController.UploadProfileImagefunc)


	userGroup.GET("/validate_token",routerControllers.UserAuthController.ValidateToken)


	authGroup := router.Group("/api/auth/user")
	authGroup.Use(infrastructure.RateLimitMiddleware())


	authGroup.POST("/register",routerControllers.UserAuthController.RegisterUser)
	authGroup.POST("/login",routerControllers.UserAuthController.Login)
	authGroup.GET("/logout",routerControllers.UserAuthController.Logout)
	authGroup.GET("/:provider",routerControllers.UserAuthController.SignInWithProvider)
	authGroup.GET("/:provider/callback",routerControllers.UserAuthController.Callback)
	authGroup.GET("/refresh",routerControllers.UserAuthController.RefreshToken)
	authGroup.GET("/verify_email",routerControllers.UserAuthController.VerifyEmail)
	authGroup.POST("/resend_verification",routerControllers.UserAuthController.ResendVerificationEmail)
	authGroup.POST("/forgot_password", routerControllers.UserAuthController.ForgotPassword)
	authGroup.POST("/reset_password", routerControllers.UserAuthController.ResetPassword)
	authGroup.POST("/Two_factor_auth", routerControllers.UserAuthController.ValidateTwoFactorAuth)
	authGroup.POST("/Two_factor_auth/resend_otp", routerControllers.UserAuthController.ResendOtp)

	authGroup.POST("/Two_factor_auth/switch",infrastructure.AuthMiddleware(jwtService), routerControllers.UserAuthController.EnableTwoFactorAuth)


	router.Run(":" + os.Getenv("PORT"))
}

