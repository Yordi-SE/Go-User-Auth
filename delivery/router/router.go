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
	router.GET("/user/get")
	router.GET("/user/get/:id")
	router.PUT("/user/update/:id")
	router.DELETE("/user/delete/:id")
	router.Run(":" + os.Getenv("PORT"))
}
