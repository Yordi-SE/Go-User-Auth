package controllers

import (
	"fmt"
	"net/http"
	models "user_authorization/domain"
	errors "user_authorization/error"
	"user_authorization/usecases"
	"user_authorization/usecases/dto"

	"github.com/gin-gonic/gin"
	"github.com/markbates/goth/gothic"
)


type UserAuthController struct {
	userAuthUseCase usecases.UserAuthI
	userUseCase usecases.UserUseCaseI
}

func NewUserAuthController(u *usecases.UserAuth,userusecase *usecases.UserUsecase ) *UserAuthController {
	return &UserAuthController{
		userAuthUseCase: u,
		userUseCase: userusecase,
	}
}

//Register user
func (u *UserAuthController) RegisterUser(c *gin.Context)  {
	user := dto.UserRegistrationDTO{}
	err := c.ShouldBindJSON(&user)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	newUser,errs := u.userAuthUseCase.CreateUser(&user)
	if errs != nil {
		c.JSON(errs.StatusCode, gin.H{"error": errs})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"message": "User created successfully",
	"data": *newUser})

}

//Login user
func (u *UserAuthController) Login(c *gin.Context) {
	user := dto.UserLoginDTO{}
	err := c.ShouldBindJSON(&user)
	fmt.Println(user.Email,user.Password)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errors.NewCustomError(err.Error(),400)})
		return 

	}

	token, errs := u.userAuthUseCase.SignIn(&user)
	if errs != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": errors.NewCustomError(errs.Message, http.StatusUnauthorized)})
		return 
	}
	// fmt.Println(token)
	c.SetCookie("access_token", token.AccessToken, 3600, "/", "localhost", false, true)
	c.SetCookie("refresh_token", token.RefreshToken, 3600*24*3, "/", "localhost", false, true)
	fmt.Println("login",token.RefreshToken)

	c.JSON(http.StatusOK,token)


}

//Logout user
func (u *UserAuthController)  Logout(c *gin.Context) {
	value, exists := c.Get("Refresh")
	if  !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": errors.NewCustomError("User not found",http.StatusBadRequest)})
		return
	}
	token, ok := value.(string)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": errors.NewCustomError("User not found",http.StatusBadRequest)})
		return		
	}
	errs := u.userAuthUseCase.SignOut(token)
	if errs != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errors.NewCustomError(errs.Error(), http.StatusBadRequest)})
		return
	}
	c.JSON(http.StatusOK,gin.H{"message":"User Logged out successfully","status":http.StatusOK})
}

//check token validity middleware
func (u *UserAuthController) CheckToken(c *gin.Context) {
	defer c.Next()
	value ,exists := c.Get("Refresh")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": errors.NewCustomError("Token not found",http.StatusUnauthorized)})
		c.Abort()
		return
	}
	token , ok := value.(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": errors.NewCustomError("Token not found",http.StatusUnauthorized)})
		c.Abort()
		return
	}
	err := u.userAuthUseCase.CheckToken(token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": errors.NewCustomError("Token not found",http.StatusUnauthorized)})
		c.Abort()
		return
	}

}


// Refresh token
func (u *UserAuthController) RefreshToken(c *gin.Context) {

	refreshToken,errs := c.Cookie("refresh_token")
	fmt.Println("refreshToken",refreshToken)
	if errs != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": errors.NewCustomError(errs.Error(),http.StatusUnauthorized)})
		return
	}
	token, err := u.userAuthUseCase.RefreshToken(&dto.RefreshTokenDTO{
		RefreshToken: refreshToken,
	})
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": errors.NewCustomError(err.Error(),http.StatusUnauthorized)})
		return
	}
	c.SetCookie("access_token", token.AccessToken, 3600, "/", "localhost", false, true)
    c.SetCookie("refresh_token", token.RefreshToken, 3600*24*3, "/", "localhost", false, true)
	c.JSON(http.StatusOK, token)
}


// Handle google Login
func (u *UserAuthController) SignInWithProvider(c *gin.Context) {
	provider := c.Param("provider")

	q := c.Request.URL.Query()
	q.Add("provider", provider)
	c.Request.URL.RawQuery = q.Encode()
	gothic.BeginAuthHandler(c.Writer, c.Request)
}


// Handle google callback
func (u *UserAuthController) Callback(c *gin.Context) {
	user := models.User{}
	provider := c.Param("provider")

	q := c.Request.URL.Query()
	q.Add("provider", provider)
	c.Request.URL.RawQuery = q.Encode()

	result, err := gothic.CompleteUserAuth(c.Writer, c.Request)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errors.NewCustomError(err.Error(),http.StatusBadRequest)})
		return
	}
	user.Email = result.Email
	user.FullName = result.Name
	user.ProfileImage = result.AvatarURL


	user.IsProviderSignIn = true
	user.IsVerified = true
	user.ProfileImage = result.AvatarURL

	token , errs := u.userAuthUseCase.HandleProviderSignIn(&user)

	if errs != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": errors.NewCustomError(errs.Error(), http.StatusUnauthorized)})
		return 
	}
	c.SetCookie("access_token", token.AccessToken, 3600, "/", "localhost", false, true)
	c.SetCookie("refresh_token", token.RefreshToken, 3600*24*3, "/", "localhost", false, true)
	c.Redirect(http.StatusFound, "http://localhost:3000/auth/backend-provider")


}


// verify email
func (u *UserAuthController) VerifyEmail(c *gin.Context) {
	token := c.Query("verification_token")
	errs := u.userAuthUseCase.VerifyEmail(token)
	if errs != nil {
		c.HTML(http.StatusOK, "verification_fail.html", gin.H{
			"title": "Verification Failed",
			"message": "The verification link is invalid or has expired.",
		})

		return
	}
	c.HTML(http.StatusOK, "verification_success.html", gin.H{
		"title": "Email Verified",
		"message": "Your email has been successfully verified.",
	})
}

// Resend verification email
func (u *UserAuthController) ResendVerificationEmail(c *gin.Context) {
	var email dto.EmailDTO
	if err := c.ShouldBindJSON(&email); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errors.NewCustomError(err.Error(),http.StatusBadRequest)})
		return
	}
	errs := u.userAuthUseCase.ResendVerificationEmail(email.Email)
	if errs != nil {
		c.JSON(errs.StatusCode, gin.H{"error": errors.NewCustomError(errs.Error(), errs.StatusCode)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Verification email sent successfully"})
}

//Forgot password
func (u *UserAuthController) ForgotPassword(c *gin.Context) {
	var email dto.EmailDTO
	if err := c.ShouldBindJSON(&email); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errors.NewCustomError(err.Error(),http.StatusBadRequest)})
		return
	}

	errs := u.userAuthUseCase.ForgotPassword(&email)
	if errs != nil {
		c.JSON(errs.StatusCode, gin.H{"error": errors.NewCustomError(errs.Error(), errs.StatusCode)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Password reset link sent successfully"})
}

//Reset password
func (u *UserAuthController) ResetPassword(c *gin.Context) {
	token := c.Query("reset_token")
	var password dto.PasswordDTO
	if err := c.ShouldBindJSON(&password); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errors.NewCustomError(err.Error(),http.StatusBadRequest)})
		return
	}
	errs := u.userAuthUseCase.ResetPassword(password.Password, token)
	if errs != nil {
		c.JSON(errs.StatusCode, gin.H{"error": errors.NewCustomError(errs.Error(), errs.StatusCode)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully"})
}

func (u *UserAuthController) ValidateToken(c *gin.Context) {
	access_token, err := c.Cookie("access_token")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": errors.NewCustomError("Invalid token claim",http.StatusUnauthorized)})
		return 
	}
	refresh_token , err:= c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": errors.NewCustomError("Invalid token claim",http.StatusUnauthorized)})
		return 
	}
	value,existis := c.Get("user_id")
	if !existis {
		c.JSON(http.StatusUnauthorized, gin.H{"error": errors.NewCustomError("Invalid token claim",http.StatusUnauthorized)})
		return 
	}
	user_id,ok := value.(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": errors.NewCustomError("Invalid token claim",http.StatusUnauthorized)})
		return 
	}

	user,errs := u.userAuthUseCase.ValidateToken(user_id)
	user.AccessToken= access_token
	user.RefreshToken = refresh_token
	if errs != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": errors.NewCustomError("Error getting session",http.StatusUnauthorized)})
		return 
	}
	c.JSON(http.StatusOK, user)
}