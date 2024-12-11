package usecases

import (
	"fmt"
	"net/http"
	models "user_authorization/domain"
	errors "user_authorization/error"
	"user_authorization/usecases/dto"
	"user_authorization/usecases/interfaces"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

//UserAuthI

type UserAuthI interface {
	CheckToken(token string) *errors.CustomError
	CreateUser(user *dto.UserRegistrationDTO) (*dto.UserResponseDTO,*errors.CustomError)
	SignOut(token string) *errors.CustomError
	SignIn(user *dto.UserLoginDTO) (*dto.UserResponseDTO,*errors.CustomError)
	RefreshToken(refreshToken *dto.RefreshTokenDTO) (*dto.TokenDTO, *errors.CustomError)
	HandleProviderSignIn(user *models.User) (*dto.UserResponseDTO, *errors.CustomError) 
	VerifyEmail(Token string) *errors.CustomError
	ResendVerificationEmail(email string) *errors.CustomError
	ForgotPassword(email *dto.EmailDTO) *errors.CustomError
	ResetPassword(password string, token string) *errors.CustomError
	ValidateToken(user_id string) (*dto.UserResponseDTO, *errors.CustomError)
}

//UserAuth struct
type UserAuth struct {
	userRepository interfaces.UserRepositoryI
	pwdService     interfaces.HashingServiceI
	jwtService     interfaces.JWTServiceI
	emailService  interfaces.EmailServiceI
	tokenRepository interfaces.TokenRepositoryI
}


//NewUserAuth creates a new UserAuth
func NewUserAuth(userRepository interfaces.UserRepositoryI, pwdService interfaces.HashingServiceI, jwtService interfaces.JWTServiceI, emailService interfaces.EmailServiceI,token interfaces.TokenRepositoryI) *UserAuth {
	return &UserAuth{
		userRepository: userRepository,
		jwtService: jwtService,
		pwdService: pwdService,
		emailService: emailService,
		tokenRepository: token,
	}
}



// CreateUser creates a new user
func (u *UserAuth) CreateUser(user *dto.UserRegistrationDTO) (*dto.UserResponseDTO,*errors.CustomError) {
	existingUser, err := u.userRepository.GetUserByEmail(user.Email)
	var newUser dto.UserResponseDTO
	if err != nil && err.StatusCode != 404 {
		return nil, errors.NewCustomError("Database error: "+err.Error(), http.StatusInternalServerError)
	}
	if existingUser != nil && existingUser.IsProviderSignIn == false {
		return nil, errors.NewCustomError("User already exists", 409)
	} else if (existingUser != nil && existingUser.IsProviderSignIn == true) {
		// Update the existing user
		Password,err := u.pwdService.HashPassword(user.Password)
		if err != nil {
			return nil, err
		}
		existingUser.Password = Password
		existingUser.FullName = user.FullName
		existingUser.PhoneNumber = user.PhoneNumber
		existingUser.IsProviderSignIn = false
		errs := u.userRepository.SaveUserUpdate(existingUser)
		if (errs != nil) {
			return nil, errs
		}
		newUser = dto.UserResponseDTO{
			UserId: existingUser.UserID,
			FullName: existingUser.FullName,
			Email: existingUser.Email,
			Role: existingUser.Role,
			PhoneNumber: existingUser.PhoneNumber,
			IsProviderSignIn: existingUser.IsProviderSignIn,
			IsVerified: existingUser.IsVerified,
			ProfileImage: existingUser.ProfileImage,
			RefreshToken: existingUser.RefreshToken,
			AccessToken: existingUser.AccessToken,
		}


	} else {
		userId := uuid.New()
		Password,err := u.pwdService.HashPassword(user.Password)
		if err != nil {
			return nil, err
		}
		user.Password = Password
		userModel := models.User{
			UserID:      userId,
			FullName:    user.FullName,
			Email:       user.Email,
			Role:		"user",
			Password:    user.Password,
			PhoneNumber: user.PhoneNumber,
		}
		token, _ := u.jwtService.GenerateVerificationToken(&userModel)
		userModel.VerificationToken = token
		result, errs := u.userRepository.CreateUser(&userModel)
		if (errs != nil) {
			return nil, errs
		}
			// Get email body
		emailBody,errss := u.emailService.GetOTPEmailBody("localhost:8080/api/auth/user/verify_email?verification_token=" + token,"otp_template.html")
		fmt.Println(errss)
		// Send verification email
		_ = u.emailService.SendEmail(result.Email, "Email Verification", emailBody,"go_auth@gmail.com")
		newUser = dto.UserResponseDTO{
			UserId: result.UserID,
			FullName: result.FullName,
			Email: result.Email,
			Role: result.Role,
			PhoneNumber: result.PhoneNumber,
			IsProviderSignIn: result.IsProviderSignIn,
			IsVerified: result.IsVerified,
			ProfileImage: result.ProfileImage,
			RefreshToken: result.RefreshToken,
			AccessToken: result.AccessToken,
		}
	}


	return &newUser,nil

}

// Signup user
func (u *UserAuth) SignIn(user *dto.UserLoginDTO) (*dto.UserResponseDTO,*errors.CustomError) {

	result, err := u.userRepository.GetUserByEmail(user.Email)
	if err != nil {
		return nil, err
	}
	fmt.Println(result.Email,user.Email, result.IsVerified)

	if !result.IsVerified {
		return nil, errors.NewCustomError("Email address is not verified.", 400)
	}
	if !u.pwdService.ComparePassword(result.Password, user.Password) {
		return nil,errors.NewCustomError("Invalid email or password", http.StatusUnauthorized)
	}
	tokenId := uuid.New()
	accessToken, refreshToken, err := u.jwtService.Generate(result,tokenId.String())
	if err != nil {
		return nil, err
	}
	result.AccessToken = accessToken
	result.RefreshToken = refreshToken
	fmt.Println(tokenId)
	tokenModel := models.Token{
		TokenID: tokenId,
		UserID: result.UserID,
		RefreshToken: refreshToken,
	}

	_,err = u.tokenRepository.CreateToken(&tokenModel)
	if err != nil {
		return nil, err
	}

	token := dto.UserResponseDTO{
		UserId: result.UserID,
		FullName: result.FullName,
		Email: result.Email,
		Role: result.Role,
		PhoneNumber: result.PhoneNumber,
		IsProviderSignIn: result.IsProviderSignIn,
		IsVerified: result.IsVerified,
		ProfileImage: result.ProfileImage,
		AccessToken: accessToken,
		RefreshToken: refreshToken,
	}
	return &token, nil

}

// Signout user
func (u *UserAuth) SignOut(token string) *errors.CustomError {
	tokenString ,err := u.jwtService.ValidateRefreshToken(token)
	if err != nil {
		return err
	}
	claims, ok := tokenString.Claims.(jwt.MapClaims)
	if !ok {
		return errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	tokenId, ok := claims["token_id"].(string)
	if !ok {
		return errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	err = u.tokenRepository.DeleteToken(tokenId)
	if err != nil {
		return err

	}
	return nil
}



// Refresh token
func (u *UserAuth) RefreshToken(refreshToken *dto.RefreshTokenDTO) (*dto.TokenDTO, *errors.CustomError) {
	// 
	token ,err := u.jwtService.ValidateRefreshToken(refreshToken.RefreshToken)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.NewCustomError("Invalid token claims", http.StatusUnauthorized)
	}
	email, ok := claims["email"].(string)
	if !ok {
		return nil, errors.NewCustomError("Invalid token claims", http.StatusUnauthorized)
	}
	role, ok := claims["role"].(string)
	if !ok {
		return nil, errors.NewCustomError("Invalid token claims", http.StatusUnauthorized)
	}
	user_id, ok := claims["user_id"].(string)

	if !ok {
		return nil, errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	userId, errs := uuid.Parse(user_id)
	if errs != nil {
		return nil, errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	tokenId, ok := claims["token_id"].(string)
	if !ok {
		return nil, errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	result, err := u.tokenRepository.GetTokenById(tokenId)
	if err != nil {
		return nil, err
	}
	token, err = u.jwtService.ValidateRefreshToken(result.RefreshToken)
	if err != nil {
		return nil, err
	}
	if result.RefreshToken != refreshToken.RefreshToken {
		return nil, errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	user := models.User {
		UserID: userId,
		Email: email,
		Role: role,
	}
	accessToken, refreshtoken,err := u.jwtService.Generate(&user,tokenId)
	if err != nil {
		return nil, err
	}
	result.RefreshToken = refreshtoken
	err = u.tokenRepository.SaveTokenUpdate(result)
	if err != nil {
		return nil, err
	}
	tokens := dto.TokenDTO{
		AccessToken: accessToken,
		RefreshToken: refreshtoken,
	}
	return &tokens, nil
}

// handle provider sign in
func (u *UserAuth) HandleProviderSignIn(user *models.User) (*dto.UserResponseDTO, *errors.CustomError) {
	existingUser, err := u.userRepository.GetUserByEmail(user.Email)
	if err != nil && err.StatusCode != 404 {
		return nil, errors.NewCustomError("Database error: "+err.Error(), http.StatusInternalServerError)
	}
	if existingUser != nil {
		// Update the existing user
		tokenId := uuid.New()
		accessToken, refreshToken, err := u.jwtService.Generate(existingUser,tokenId.String())

		if err != nil {
			return nil, err
		}
		existingUser.IsVerified = true
		err = u.userRepository.SaveUserUpdate(existingUser)
		if err != nil {
			return nil, err
		}
		tokenModel := models.Token{
			UserID: existingUser.UserID,
			TokenID: tokenId,
			RefreshToken: refreshToken,
		}
		_,err = u.tokenRepository.CreateToken(&tokenModel)
		if err != nil {
			return nil, err
		}
		newUser := dto.UserResponseDTO{
			UserId: existingUser.UserID,
			FullName: existingUser.FullName,
			Email: existingUser.Email,
			Role: existingUser.Role,
			PhoneNumber: existingUser.PhoneNumber,
			IsProviderSignIn: existingUser.IsProviderSignIn,
			IsVerified: existingUser.IsVerified,
			ProfileImage: existingUser.ProfileImage,
			RefreshToken: refreshToken,
			AccessToken: accessToken,
		}
		return &newUser, nil
	}
	user.Role = "user"
	user.UserID = uuid.New()
	tokeId := uuid.New()
	accessToken, refreshToken, err := u.jwtService.Generate(user,tokeId.String())
	if err != nil {
		return nil, err
	}
	user.AccessToken = accessToken
	user.RefreshToken = refreshToken
	tokenModel := models.Token{
		UserID: user.UserID,
		TokenID: tokeId,
		RefreshToken: refreshToken,
	}
	_,err = u.tokenRepository.CreateToken(&tokenModel)
		if err != nil {
		return nil, err

	}
	userModel, err := u.userRepository.CreateUser(user)
	if err != nil {
		return nil, err

	}

	response := dto.UserResponseDTO{
		UserId: userModel.UserID,
		FullName: userModel.FullName,
		Email: userModel.Email,
		Role: userModel.Role,
		PhoneNumber: userModel.PhoneNumber,
		IsProviderSignIn: userModel.IsProviderSignIn,
		IsVerified: userModel.IsVerified,
		ProfileImage: userModel.ProfileImage,
		AccessToken: userModel.AccessToken,
		RefreshToken: userModel.RefreshToken,
	}
	return &response, nil
}

// verify user email
func (u *UserAuth) VerifyEmail(Token string) *errors.CustomError {
	token, err := u.jwtService.ValidateVerificationToken(Token)
	if err != nil {
		return err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	id, ok := claims["user_id"].(string)
	if !ok {
		return errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	user, err := u.userRepository.GetUserById(id)
	if err != nil {
		return err
	}
	if user.VerificationToken != Token {
		return errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	user.IsVerified = true
	user.VerificationToken = ""
	err = u.userRepository.SaveUserUpdate(user)
	if err != nil {
		return err
	}
	return nil
}

// Resend verification email
func (u *UserAuth) ResendVerificationEmail(email string) *errors.CustomError {
	user, err := u.userRepository.GetUserByEmail(email)
	if err != nil {
		return err
	}
	if user.IsVerified {
		return errors.NewCustomError("User already verified", http.StatusConflict)
	}
	token, err := u.jwtService.GenerateVerificationToken(user)
	if err != nil {
		return err
	}
	user.VerificationToken = token
	err = u.userRepository.SaveUserUpdate(user)
	if err != nil {
		return err
	}
	// Get email body
	emailBody,errs := u.emailService.GetOTPEmailBody("localhost:8080/api/auth/user/verify_email?verification_token=" + token,"otp_template.html")
	if errs != nil {
		return errors.NewCustomError("Error getting email body", http.StatusInternalServerError)
	}
	// Send verification email
	e := u.emailService.SendEmail(user.Email, "Email Verification", emailBody,"go_auth@gmail.com")
	if e != nil {
		return errors.NewCustomError("Error sending email", http.StatusInternalServerError)
	}
	return nil
}


//Forgot Password
func (u *UserAuth) ForgotPassword(email *dto.EmailDTO) *errors.CustomError {
	user, err := u.userRepository.GetUserByEmail(email.Email)
	if err != nil {
		return err
	}
	token, err := u.jwtService.GeneratePasswordResetToken(user)
	if err != nil {
		return err
	}

	// Get email body
	user.PasswordResetToken = token
	err = u.userRepository.SaveUserUpdate(user)
	if err != nil {
		return err
	}
	emailBody, errs := u.emailService.GetOTPEmailBody("localhost:8080/api/auth/user/reset_password?reset_token=" + token,"password_verification.html")
	if errs != nil {
		return errors.NewCustomError(errs.Error(), http.StatusInternalServerError)
	}

	// Send verification email
	e := u.emailService.SendEmail(user.Email, "Password Reset", emailBody,"noreplay@gmail.com")
	if e != nil {
		return errors.NewCustomError(e.Error(), http.StatusInternalServerError)
	}

	return nil


}

//reset Password
func (u *UserAuth) ResetPassword(password string, token string) *errors.CustomError {
	Token, err := u.jwtService.ValidePasswordResetToken(token)
	if err != nil {
		return err
	}
	claims, ok := Token.Claims.(jwt.MapClaims)
	if !ok || !Token.Valid {
		return errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	id, ok := claims["user_id"].(string)
	if !ok {
		return errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	user, err := u.userRepository.GetUserById(id)
	if err != nil {
		return err
	}
	if user.PasswordResetToken != token {
		return errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	password , err = u.pwdService.HashPassword(password)
	if err != nil {
		return err
	}
	user.Password = password
	user.PasswordResetToken = ""
	err = u.userRepository.SaveUserUpdate(user)
	if err != nil {
		return err
	}
	return nil
}

func (u *UserAuth) ValidateToken(user_id string) (*dto.UserResponseDTO, *errors.CustomError) {

	user, err := u.userRepository.GetUserById(user_id)
	if err != nil {
		return nil, err
	}

	response := dto.UserResponseDTO{
		UserId: user.UserID,
		FullName: user.FullName,
		Email: user.Email,
		Role: user.Role,
		PhoneNumber: user.PhoneNumber,
		IsProviderSignIn: user.IsProviderSignIn,
		IsVerified: user.IsVerified,
		ProfileImage: user.ProfileImage,
		AccessToken: user.AccessToken,
		RefreshToken: user.RefreshToken,
	}
	return &response, nil
}

func (u *UserAuth) CheckToken(token string) *errors.CustomError {
	tokenString ,err := u.jwtService.ValidateRefreshToken(token)
	if err != nil {
		return err
	}
	claims, ok := tokenString.Claims.(jwt.MapClaims)
	if !ok {
		return errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	tokenId, ok := claims["token_id"].(string)
	if !ok {
		return errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	result, err := u.tokenRepository.GetTokenById(tokenId)
	if err != nil {
		return err
	}
	fmt.Println("checktoken 2",result.RefreshToken)
	tokenString, err = u.jwtService.ValidateRefreshToken(result.RefreshToken)
	if err != nil {
		return err
	}
	if result.RefreshToken != token {
		return errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	return nil
}