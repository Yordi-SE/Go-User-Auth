package controllers

import (
	"net/http"
	"strconv"
	"user_authorization/usecases"
	"user_authorization/usecases/dto"

	"github.com/gin-gonic/gin"
)

type UserController struct {
	userUseCase usecases.UserUseCaseI

}

func NewUserController(u usecases.UserUseCaseI) *UserController {
	return &UserController{
		userUseCase: u,
	}
}

//Register user
func (u *UserController) RegisterUser(c *gin.Context)  {
	user := dto.UserRegistrationDTO{}
	err := c.ShouldBindJSON(&user)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	newUser,err := u.userUseCase.CreateUser(&user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"message": "User created successfully",
	"data": *newUser})

}

//GetUsers gets 20 users per page
func (u *UserController) GetUsers(c *gin.Context) {
	pageNumber, err := strconv.Atoi(c.Query("page"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	users, err := u.userUseCase.GetUsers(pageNumber)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"users": users})
}