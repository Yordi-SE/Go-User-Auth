package repositories

import (
	errorss "errors"
	models "user_authorization/domain"

	"gorm.io/gorm"

	errors "user_authorization/error"
)

type TokenRepository struct {
	db *gorm.DB
}

// NewUserRepository
func NewTokenRepository(db *gorm.DB) *TokenRepository {
	return &TokenRepository{db}
}
//createUser creates a new user
func (r *TokenRepository) CreateToken(token *models.Token) (*models.Token, *errors.CustomError) {
    // Create a new user
    if err := r.db.Table("tokens").Create(&token).Error; err != nil {
        return nil, errors.NewCustomError(err.Error(), 500)
    }
    return token, nil
}

func (r *TokenRepository) GetTokenById(tokenId string) (*models.Token, *errors.CustomError) {
    var token models.Token
    if err := r.db.Table("tokens").Where("token_id = ?", tokenId).First(&token).Error; err != nil {
        if errorss.Is(err,gorm.ErrRecordNotFound) {
            return nil, errors.NewCustomError("token not found", 404)
        }
        return nil, errors.NewCustomError("error getting token", 500)
    }
    return &token, nil
}


//update user password
func (r *TokenRepository) SaveTokenUpdate(token *models.Token) *errors.CustomError {
    if err := r.db.Table("tokens").Save(&token).Error; err != nil {
        return errors.NewCustomError("error updating token", 500)
    }
    return nil
}


func (r *TokenRepository) DeleteToken(tokenId string) *errors.CustomError {
    // Use GORM's delete method to remove the user
    if err := r.db.Table("tokens").Delete(&models.Token{}, "token_id = ?", tokenId).Error; err != nil {
        return errors.NewCustomError("error deleting tokens", 500)
    }

    return nil
}
