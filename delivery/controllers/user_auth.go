package controllers

import (
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
}

func NewUserAuthController(u *usecases.UserAuth) *UserAuthController {
	return &UserAuthController{
		userAuthUseCase: u,
	}
}

//Login user
func (u *UserAuthController) Login(c *gin.Context) {
	user := dto.UserLoginDTO{}
	err := c.ShouldBindJSON(&user)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errors.NewCustomError(err.Error(),400)})
		return 

	}

	token, errs := u.userAuthUseCase.SignIn(&user)
	if errs != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errors.NewCustomError(errs.Message, errs.StatusCode)})
		return 
	}

	c.JSON(http.StatusOK,token)


}

//Logout user
func (u *UserAuthController)  Logout(c *gin.Context) {
	value,exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": errors.NewCustomError("User not found",http.StatusBadRequest)})
		return
	}
	useId,ok := value.(string)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": errors.NewCustomError("User not found",http.StatusBadRequest)})
		return
	}
	errs := u.userAuthUseCase.SignOut(useId)
	if errs != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errors.NewCustomError(errs.Error(), http.StatusBadRequest)})
		return
	}
	c.JSON(http.StatusOK,gin.H{"message":"User Logged out successfully","status":http.StatusOK})
}

//check token validity middleware
func (u *UserAuthController) CheckToken(c *gin.Context) {
	defer c.Next()
	token ,exists := c.Get("Authorization")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": errors.NewCustomError("Token not found",http.StatusUnauthorized)})
		c.Abort()
		return
	}
	id ,exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": errors.NewCustomError("User not found",http.StatusUnauthorized)})
		c.Abort()
		return
	}
	userId,ok := id.(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": errors.NewCustomError("User not found",http.StatusUnauthorized)})
		c.Abort()
		return
	}
	userToken,errs := u.userAuthUseCase.GetTokens(userId)
	if errs != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errors.NewCustomError(errs.Error(), http.StatusBadRequest)})
		c.Abort()
		return
	}
	if userToken.AccessToken != token {
		c.JSON(http.StatusUnauthorized, gin.H{"error": errors.NewCustomError("Invalid token",http.StatusUnauthorized)})
		c.Abort()
		return
	}

}


// Refresh token
func (u *UserAuthController) RefreshToken(c *gin.Context) {
	var refreshToken dto.RefreshTokenDTO
	if err := c.ShouldBindJSON(&refreshToken); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errors.NewCustomError(err.Error(),http.StatusBadRequest)})
		return
	}
	token, err := u.userAuthUseCase.RefreshToken(&refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": errors.NewCustomError(err.Error(),http.StatusUnauthorized)})
		return
	}
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
	// fmt.Print(result)

	if err != nil {
		c.AbortWithError(http.StatusBadRequest, errors.NewCustomError(err.Error(),http.StatusBadRequest))
		c.JSON(http.StatusBadRequest, gin.H{"error": errors.NewCustomError(err.Error(),http.StatusBadRequest)})
		return
	}
	user.Email = result.Email
	user.FullName = result.Name
	user.ProfileImage = result.AvatarURL


	user.IsProviderSignIn = true
	value := result.RawData["verified_email"]
	IsVerified, ok := value.(bool)
	if ok {
		user.IsVerified = IsVerified
	} else {
		user.IsVerified = false
	}
	user.ProfileImage = result.AvatarURL

	tokens , errs := u.userAuthUseCase.HandleProviderSignIn(&user)
	if errs != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": errors.NewCustomError(errs.Error(), http.StatusUnauthorized)})
		return 
	}
	c.JSON(http.StatusOK, gin.H{"token": tokens})


}