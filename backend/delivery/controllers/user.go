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



//GetUsers gets 20 users per page
func (u *UserController) GetUsers(c *gin.Context) {
	pageNumber, err := strconv.Atoi(c.Query("page"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	users, errs := u.userUseCase.GetUsers(pageNumber)
	if errs != nil {
		c.JSON(errs.StatusCode, gin.H{"error": errs})
		return
	}
	c.JSON(http.StatusOK, gin.H{"users": users})
}

// GetUsers by Id
func (u *UserController) GetUserById(c *gin.Context) {
	userId := c.Param("id")
	user, err := u.userUseCase.GetUserById(userId)
	if err != nil {
		c.JSON(err.StatusCode, gin.H{"error": err})
		return
	}	
	c.JSON(http.StatusOK, gin.H{"user": user})
}

// Update user
func (u *UserController) UpdateUser(c *gin.Context) {
	userId := c.Param("id")
	user := dto.UserUpdateDTO{}
	err := c.ShouldBindJSON(&user)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	errs := u.userUseCase.UpdateUser(userId, &user)
	if errs != nil {
		c.JSON(errs.StatusCode, gin.H{"error": errs})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "User updated successfully"})
}


// Delete user
func (u *UserController) DeleteUser(c *gin.Context) {
	userId := c.Param("id")
	err := u.userUseCase.DeleteUser(userId)
	if err != nil {
		c.JSON(err.StatusCode, gin.H{"error": err})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "User delete successfully"})
}

// Profile image upload
func (u *UserController) UploadProfileImagefunc(c *gin.Context) {
 // Get the image from request body
 id := c.Param("id")

 file, err := c.FormFile("profile_pic")
 if err != nil {
  c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
  return
 }

 // Upload the image locally
 err = c.SaveUploadedFile(file, "../assets/uploads/"+file.Filename)

 if err != nil {
  c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save profile image"})
  return
 }
 SecureUrl, errs := u.userUseCase.UploadProfilePic(id, file)

 if errs != nil {
	  c.JSON(errs.StatusCode, gin.H{"error": errs})
	  return
	   }

	c.JSON(http.StatusOK, gin.H{"message": "Profile image uploaded successfully", "secure_url": SecureUrl})
 }