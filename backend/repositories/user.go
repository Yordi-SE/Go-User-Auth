package repositories

import (
	"fmt"
	models "user_authorization/domain"

	"gorm.io/gorm"

	errors "user_authorization/error"
)




type UserRepository struct {
	db *gorm.DB
}

// NewUserRepository
func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db}
}

//createUser creates a new user
func (r *UserRepository) CreateUser(user *models.User) (*models.User, *errors.CustomError) {
    // Create a new user
    if err := r.db.Table("users").Create(&user).Error; err != nil {
        return nil, errors.NewCustomError(err.Error(), 500)
    }
    return user, nil
}

//getUsers gets 20 users per page
func (r *UserRepository) GetUsers(page int) ([]models.User, *errors.CustomError) {
    const itemsPerPage = 20
    if page < 1 {
        page = 1
    }
    offset := (page - 1) * itemsPerPage
    var users []models.User
    if err := r.db.Table("users").Limit(itemsPerPage).Offset(offset).Find(&users).Error; err != nil {
        return nil, errors.NewCustomError("error getting users", 500)
    }

    if len(users) == 0 {
        return nil, errors.NewCustomError("no users found", 404)
    }

    return users, nil
}


//getUserById gets a user by id
func (r *UserRepository) GetUserById(userId string) (*models.User, *errors.CustomError) {
    var user models.User
    if err := r.db.Table("users").Where("user_id = ?", userId).First(&user).Error; err != nil {
        if err == gorm.ErrRecordNotFound {
            return nil, errors.NewCustomError("user not found", 404)
        }
        return nil, errors.NewCustomError("error getting user", 500)
    }
    return &user, nil
}

//getUserByEmail gets a user by email
func (r *UserRepository) GetUserByEmail(email string) (*models.User, *errors.CustomError) {
    user := models.User{}
    if err := r.db.Table("users").Where("email = ?", email).First(&user).Error; err != nil {
            fmt.Println(err)

        if err == gorm.ErrRecordNotFound {
            return nil, errors.NewCustomError("user not found", 404)
        }
        return nil, errors.NewCustomError("error getting user", 500)
    }
    return &user, nil
}




//DeleteUser deletes a user
func (r *UserRepository) DeleteUser(userId string) *errors.CustomError {
    // Use GORM's delete method to remove the user
    if err := r.db.Table("users").Delete(&models.User{}, "user_id = ?", userId).Error; err != nil {
        return errors.NewCustomError("error deleting user", 500)
    }

    return nil
}


//Update user Token
func (r *UserRepository) UpdateUserToken(userId string, accessToken string, refreshToken string) *errors.CustomError {
    var user models.User
    if err := r.db.Table("users").First(&user, "user_id = ?", userId).Error; err != nil {
        return errors.NewCustomError("user not found", 404)
    }
    user.AccessToken = accessToken
    user.RefreshToken = refreshToken
    if err := r.db.Save(&user).Error; err != nil {
        return errors.NewCustomError("error updating user token", 500)
    }
    return nil
}

//update user password
func (r *UserRepository) SaveUserUpdate(user *models.User) *errors.CustomError {
    if err := r.db.Table("users").Save(&user).Error; err != nil {
        return errors.NewCustomError("error updating user", 500)
    }
    return nil
}
