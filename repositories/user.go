package repositories

import (
	errorss "errors"
	models "user_authorization/domain"

	"gorm.io/gorm"

	errors "user_authorization/error"
)

// UserRepository interface
type UserRepositoryI interface {
CreateUser(user *models.User) (*models.User, *errors.CustomError)
	GetUserByEmail(email string) (*models.User, error)
	GetUserById(userId string) (*models.User, error)
}


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
    if err := r.db.Create(&user).Error; err != nil {
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
    if err := r.db.Limit(itemsPerPage).Offset(offset).Find(&users).Error; err != nil {
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
    if err := r.db.Where("user_id = ?", userId).First(&user).Error; err != nil {
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
    if err := r.db.Where("email = ?", email).First(&user).Error; err != nil {
        if errorss.Is(err, gorm.ErrRecordNotFound){
            
            return nil, errors.NewCustomError("user not found", 404)
        }
        return nil, errors.NewCustomError("error getting user", 500)
    }
    return &user, nil
}

//updateUser by id
func (r *UserRepository) UpdateUser(userId string, user *models.User) *errors.CustomError {
    var existingUser models.User
    if err := r.db.First(&existingUser, "user_id = ?", userId).Error; err != nil {
        return errors.NewCustomError("user not found", 404)
    }

    if user.FullName != "" {
        existingUser.FullName = user.FullName
    }
    if user.PhoneNumber != "" {
        existingUser.PhoneNumber = user.PhoneNumber
    }
    if user.ProfileImage != "" {
        existingUser.ProfileImage = user.ProfileImage
    }

    // Save the changes
    if err := r.db.Save(&existingUser).Error; err != nil {
        return errors.NewCustomError("error updating user", 500)
    }

    return nil
}

//updateUser verificatons status
func (r *UserRepository) UpdateUserVerificationStatus(userId string,  user *models.User) *errors.CustomError {
    var existingUser models.User
    if err := r.db.First(&existingUser, "user_id = ?", userId).Error; err != nil {
        if err == gorm.ErrRecordNotFound {

        return errors.NewCustomError("user not found", 404)
        }
        return errors.NewCustomError("error getting user", 500)
    }
    existingUser.IsVerified = user.IsVerified
    existingUser.VerificationToken = user.VerificationToken
    if err := r.db.Save(&user).Error; err != nil {
        return errors.NewCustomError("error updating user verification status", 500)
    }
    return nil
}

//DeleteUser deletes a user
func (r *UserRepository) DeleteUser(userId string) *errors.CustomError {
    // Use GORM's delete method to remove the user
    if err := r.db.Delete(&models.User{}, "user_id = ?", userId).Error; err != nil {
        return errors.NewCustomError("error deleting user", 500)
    }

    return nil
}


//Update user Token
func (r *UserRepository) UpdateUserToken(userId string, accessToken string, refreshToken string) *errors.CustomError {
    var user models.User
    if err := r.db.First(&user, "user_id = ?", userId).Error; err != nil {
        return errors.NewCustomError("user not found", 404)
    }
    user.AccessToken = accessToken
    user.RefreshToken = refreshToken
    if err := r.db.Save(&user).Error; err != nil {
        return errors.NewCustomError("error updating user token", 500)
    }
    return nil
}