package controllers

import (
	"net/http"
	errors "user_authorization/error"
	"user_authorization/usecases"
	"user_authorization/usecases/dto"

	"github.com/gin-gonic/gin"
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