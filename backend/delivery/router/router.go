package router

import (
	"os"
	"time"
	"fmt"
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
	router.Use(func(c *gin.Context) {
		referer := c.Request.Referer()
		fmt.Println("Request received from:", referer)
		c.Next()
	})
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{os.Getenv("FRONT_END_URL")}
	config.AllowCredentials = true
	config.AllowMethods = []string{"GET", "POST", "PUT", "DELETE","OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Content-Length", "Content-Type", "Authorization","access-control-allow-origin","access-control-allow-headers","access-control-allow-methods","access-control-allow-credentials","Accept", "User-Agent", "Cache-Control"}
	config.ExposeHeaders = []string{"Content-Length"}
	config.MaxAge = 12 * time.Hour
	router.Use(cors.New(config))
	router.LoadHTMLFiles("/app/delivery/templates/verification_success.html", "/app/delivery/templates/verification_fail.html")

	jwtService := routerService.JwtService

	userGroup := router.Group("/api/user")
	userGroup.Use(infrastructure.RateLimitMiddleware())
	userGroup.Use(infrastructure.AuthMiddleware(jwtService))

	userGroup.Use(routerControllers.UserAuthController.CheckToken)
	userGroup.Use(infrastructure.SecureHeadersMiddleware())

	userGroup.GET("/get",infrastructure.AdminAuthMiddleware(jwtService),routerControllers.UserController.GetUsers)
	userGroup.GET("/get/:id",infrastructure.UserAuthMiddleware(jwtService),routerControllers.UserController.GetUserById)
	userGroup.PUT("/update/:id",infrastructure.UserAuthMiddleware(jwtService),routerControllers.UserController.UpdateUser)
	userGroup.DELETE("/delete/:id",infrastructure.UserAuthMiddleware(jwtService),routerControllers.UserController.DeleteUser)
	userGroup.POST("/upload/:id",infrastructure.UserAuthMiddleware(jwtService),routerControllers.UserController.UploadProfileImagefunc)




	authGroup := router.Group("/api/auth/user")
	authGroup.Use(infrastructure.RateLimitMiddleware())
	authGroup.Use(infrastructure.SecureHeadersMiddleware())


	authGroup.POST("/register",routerControllers.UserAuthController.RegisterUser)
	authGroup.POST("/login",routerControllers.UserAuthController.Login)
	authGroup.GET("/logout",infrastructure.AuthMiddleware(jwtService),routerControllers.UserAuthController.CheckToken,routerControllers.UserAuthController.Logout)
	authGroup.GET("/:provider",routerControllers.UserAuthController.SignInWithProvider)
	authGroup.GET("/:provider/callback",routerControllers.UserAuthController.Callback)
	authGroup.POST("/refresh",routerControllers.UserAuthController.RefreshToken)
	authGroup.GET("/verify_email",routerControllers.UserAuthController.VerifyEmail)
	authGroup.POST("/resend_verification",routerControllers.UserAuthController.ResendVerificationEmail)
	authGroup.POST("/forgot_password", routerControllers.UserAuthController.ForgotPassword)
	authGroup.POST("/reset_password", routerControllers.UserAuthController.ResetPassword)
	authGroup.POST("/Two_factor_auth", routerControllers.UserAuthController.ValidateTwoFactorAuth)
	authGroup.POST("/Two_factor_auth/resend_otp", routerControllers.UserAuthController.ResendOtp)
	authGroup.GET("/validate_token",routerControllers.UserAuthController.ValidateToken)


	authGroup.POST("/Two_factor_auth/switch",infrastructure.AuthMiddleware(jwtService), routerControllers.UserAuthController.EnableTwoFactorAuth)


	router.Run(":" + os.Getenv("PORT"))
}

 
