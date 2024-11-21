package repositories

import (
	"database/sql"
	"fmt"
	models "user_authorization/domain"
)

// UserRepository interface
type UserRepositoryI interface {
	CreateUser(user *models.User) error
	GetUserByEmail(email string) (*models.User, error)
	GetUserById(userId string) (*models.User, error)
}


type UserRepository struct {
	db *sql.DB
}

// NewUserRepository
func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db}
}

//createUser creates a new user
func  (r *UserRepository) CreateUser(user *models.User) (*models.User, error) {
	// Create a new user
	fmt.Println("Creating user", user)

	_, err := r.db.Exec(
    "INSERT INTO users (user_id, full_name, email, password, role, phone_number, is_provider_sign_in, is_verified, profile_image, refresh_token, access_token) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    user.UserId, user.FullName, user.Email, user.Password, user.Role, user.PhoneNumber, user.IsProviderSignIn, user.IsVerified, user.ProfileImage, user.RefreshToken, user.AccessToken,
)
	if err != nil {
		return nil,err
	}
		newUser := models.User{
			UserId: user.UserId,
			FullName: user.FullName,
			Email: user.Email,
			Role: user.Role,
			PhoneNumber: user.PhoneNumber,
			IsProviderSignIn: user.IsProviderSignIn,
			IsVerified: user.IsVerified,
			ProfileImage: user.ProfileImage,
			RefreshToken: user.RefreshToken,
			AccessToken: user.AccessToken,
			
		}
	fmt.Println("User created successfully", newUser)
	return &newUser, nil
}

//getUsers gets 20 users per page
func (r *UserRepository) GetUsers(page int) ([]models.User, error) {
	// Get 20 users per page

	results, err := r.db.Query("SELECT * FROM users LIMIT 20 OFFSET ?", page)
	if err != nil {
		return nil,err
	}
	defer results.Close()
	users := []models.User{}
	for results.Next() {
		user := models.User{}
		err := results.Scan(&user.UserId, &user.FullName, &user.Email, &user.Role, &user.PhoneNumber, &user.IsProviderSignIn, &user.IsVerified, &user.ProfileImage, &user.RefreshToken, &user.AccessToken)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, nil
}

//getUserByEmail gets a user by email
func (r *UserRepository)GetUserByEmail(email string) (*models.User, error) {
	// Get a user by email


	results, err := r.db.Query("SELECT * FROM users WHERE email = ?", email)
	if err != nil {
		return nil, err
	}
	defer results.Close()
	user := models.User{}
	for results.Next() {
		err := results.Scan(&user.UserId, &user.FullName, &user.Email, &user.Role, &user.PhoneNumber, &user.IsProviderSignIn, &user.IsVerified, &user.ProfileImage, &user.RefreshToken, &user.AccessToken)
		if err != nil {
			return nil, err
		}
	}
	return &user, nil
}

//getUserById gets a user by id
func (r *UserRepository)GetUserById(userId string) (*models.User, error) {
	// Get a user by id
	
	results, err := r.db.Query("SELECT * FROM users WHERE user_id = ?", userId)
	if err != nil {
		return nil, err
	}
	defer results.Close()
	user := models.User{}
	for results.Next() {
		err := results.Scan(&user.UserId, &user.FullName, &user.Email,  &user.Role, &user.PhoneNumber, &user.IsProviderSignIn, &user.IsVerified, &user.ProfileImage, &user.RefreshToken, &user.AccessToken)
		if err != nil {
			return nil, err
		}
	}
	return &user, nil
}

//updateUser by id
func (r *UserRepository) UpdateUser(userId string, user *models.User) error {
	// Update a user by id
	
	results, err := r.db.Query("UPDATE users SET full_name = ?,   phone_number = ?,   profile_image = ?, WHERE user_id = ?", user.FullName,  user.PhoneNumber,  user.ProfileImage,  userId)
	if err != nil {
		return err
	}
	defer results.Close()
	return nil
}

//DeleteUser deletes a user
func (r *UserRepository) DeleteUser(userId string) error {
	results, err := r.db.Query("DELETE FROM users WHERE user_id = ?", userId)
	if err != nil {
		return err
	}
	defer results.Close()
	return nil
}