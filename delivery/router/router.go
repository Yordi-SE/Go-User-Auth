package router

import (
	"os"
	"user_authorization/delivery/controllers"

	"github.com/gin-gonic/gin"
)

type RouterControllers struct {
	UserController *controllers.UserController
}

func NewRouter ( routerControllers *RouterControllers)  {
	router := gin.Default()

	router.POST("/user/register",routerControllers.UserController.RegisterUser)
	router.GET("/user/get",routerControllers.UserController.GetUsers)
	router.GET("/user/get/:id",routerControllers.UserController.GetUserById)
	router.PUT("/user/update/:id",routerControllers.UserController.UpdateUser)
	router.DELETE("/user/delete/:id",routerControllers.UserController.DeleteUser)
	router.Run(":" + os.Getenv("PORT"))
}
