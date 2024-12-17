package usecases

import (
	"net/http"
	"time"
	models "user_authorization/domain"
	errors "user_authorization/error"
	"user_authorization/usecases/dto"
	"user_authorization/usecases/interfaces"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
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
	EnableTwoFactorAuthentication(email string) *errors.CustomError
	TwoFactorAuthenticationVerification(email string,otpCode string, otpToken string) (*dto.UserResponseDTO,*errors.CustomError)
	ResendOTPCode(email string,otpToken string) *errors.CustomError	
}

//UserAuth struct
type UserAuth struct {
	UserRepository interfaces.UserRepositoryI
	PwdService     interfaces.HashingServiceI
	JwtService     interfaces.JWTServiceI
	EmailService  interfaces.EmailServiceI
	TokenRepository interfaces.TokenRepositoryI
	TwoFactorSecretKey string
	CacheRepository interfaces.CacheRepositoryI
}


//NewUserAuth creates a new UserAuth
func NewUserAuth(userRepository interfaces.UserRepositoryI, pwdService interfaces.HashingServiceI, jwtService interfaces.JWTServiceI, emailService interfaces.EmailServiceI,token interfaces.TokenRepositoryI,TwoFactorSecretKey string,cacheRepository interfaces.CacheRepositoryI) *UserAuth {
	return &UserAuth{
		UserRepository: userRepository,
		JwtService: jwtService,
		PwdService: pwdService,
		EmailService: emailService,
		TokenRepository: token,
		TwoFactorSecretKey: TwoFactorSecretKey,
		CacheRepository: cacheRepository,
	}
}



// CreateUser  creates a new user
func (u *UserAuth) CreateUser(user *dto.UserRegistrationDTO) (*dto.UserResponseDTO,*errors.CustomError) {
	existingUser, err := u.UserRepository.GetUserByEmail(user.Email)
	var newUser dto.UserResponseDTO
	if err != nil && err.StatusCode != 404 {
		return nil, errors.NewCustomError("Database error: "+err.Error(), http.StatusInternalServerError)
	}
	if existingUser != nil && existingUser.IsProviderSignIn == false {
		return nil, errors.NewCustomError("User already exists", 400)
	} else if (existingUser != nil && existingUser.IsProviderSignIn == true) {
		// Update the existing user
		Password,err := u.PwdService.HashPassword(user.Password)
		if err != nil {
			return nil, err
		}
		existingUser.Password = Password
		existingUser.FullName = user.FullName
		existingUser.PhoneNumber = user.PhoneNumber
		existingUser.IsProviderSignIn = false
		errs := u.UserRepository.SaveUserUpdate(existingUser)
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
			TwoFactorAuth: existingUser.TwoFactorAuth,
		}


	} else {
		userId := uuid.New()
		Password,err := u.PwdService.HashPassword(user.Password)
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
		token, _ := u.JwtService.GenerateVerificationToken(&userModel)
		result, errs := u.UserRepository.CreateUser(&userModel)
		if (errs != nil) {
			return nil, errs
		}
		_ = u.CacheRepository.Set(userModel.Email + "verification_token", token, 30*time.Minute)
		// Get email body
		emailBody,_ := u.EmailService.GetOTPEmailBody("localhost:8080/api/auth/user/verify_email?verification_token=" + token,"email_verification.html")
		//.Println(errss)
		// Send verification email
		_ = u.EmailService.SendEmail(result.Email, "Email Verification", emailBody,"go_auth@gmail.com")
		newUser = dto.UserResponseDTO{
			UserId: result.UserID,
			FullName: result.FullName,
			Email: result.Email,
			Role: result.Role,
			PhoneNumber: result.PhoneNumber,
			IsProviderSignIn: result.IsProviderSignIn,
			IsVerified: result.IsVerified,
			ProfileImage: result.ProfileImage,
			TwoFactorAuth: result.TwoFactorAuth,
		}
	}


	return &newUser,nil

}

// Signup user
func (u *UserAuth) SignIn(user *dto.UserLoginDTO) (*dto.UserResponseDTO,*errors.CustomError) {

	result, err := u.UserRepository.GetUserByEmail(user.Email)
	if err != nil {
		return nil, err
	}
	//.Println(result.Email,user.Email, result.IsVerified)

	if !result.IsVerified {
		return nil, errors.NewCustomError("Email address is not verified.", http.StatusUnauthorized)
	}
	if !u.PwdService.ComparePassword(result.Password, user.Password) {
		return nil,errors.NewCustomError("Invalid email or password", http.StatusUnauthorized)
	}

	if result.TwoFactorAuth {
		otp_token, errr := u.JwtService.GenerateOtpToken(result)
		if errr != nil {
			return nil, err
		}
		SecretKey := u.TwoFactorSecretKey
		otpCode, err := totp.GenerateCode(SecretKey, time.Now())
		if err != nil {
			return nil, errors.NewCustomError(err.Error(), http.StatusInternalServerError)
		}
		errr = u.CacheRepository.Set(result.Email + "otp_code", otpCode, 15*time.Minute)
		if errr != nil {
			return nil, errr
		}

		errr = u.CacheRepository.Set(result.Email + "otp_Token", otp_token, 15*time.Minute)
		if errr != nil {
			return nil, errr
		}
		emailBody,_ := u.EmailService.GetOTPEmailBody(otpCode,"otp_verification.html")

		_ = u.EmailService.SendEmail(result.Email, "Two Factor Authentication", emailBody,"go_auth@gmail.com")

		return &dto.UserResponseDTO{
			TwoFactorAuth: result.TwoFactorAuth,
			Email: result.Email,
			FullName: result.FullName,
			Role: result.Role,
			PhoneNumber: result.PhoneNumber,
			IsProviderSignIn: result.IsProviderSignIn,
			IsVerified: result.IsVerified,
			ProfileImage: result.ProfileImage,
			OTPToken: otp_token, 
		},nil
	}
	tokenId := uuid.New()
	accessToken, refreshToken, err := u.JwtService.Generate(result,tokenId.String())
	if err != nil {
		return nil, err
	}

	err = u.CacheRepository.Set(result.UserID.String() + tokenId.String(), refreshToken, 72 *time.Hour)
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
	tokenString ,err := u.JwtService.ValidateRefreshToken(token)
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
	err = u.TokenRepository.DeleteToken(tokenId)
	if err != nil {
		return err

	}
	return nil
}



// Refresh token
func (u *UserAuth) RefreshToken(refreshToken *dto.RefreshTokenDTO) (*dto.TokenDTO, *errors.CustomError) {
	// 
	token ,err := u.JwtService.ValidateRefreshToken(refreshToken.RefreshToken)
	if err != nil {
		return nil, err
	}
	if token == nil || !token.Valid {
		return nil, errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok  {
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
	result, err := u.CacheRepository.Get(userId.String() + tokenId)
	if err != nil {
		return nil, err
	}
	if result != refreshToken.RefreshToken {
		return nil, errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	user := models.User {
		UserID: userId,
		Email: email,
		Role: role,
	}
	accessToken, refreshtoken,err := u.JwtService.Generate(&user,tokenId)
	if err != nil {
		return nil, err
	}
	result = refreshtoken
	err = u.CacheRepository.Set(userId.String() + tokenId, refreshtoken, 72 * time.Hour)
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
	existingUser, err := u.UserRepository.GetUserByEmail(user.Email)
	if err != nil && err.StatusCode != 404 {
		return nil, errors.NewCustomError("Database error: "+err.Error(), http.StatusInternalServerError)
	}
	if existingUser != nil {
		// Update the existing user
		tokenId := uuid.New()
		accessToken, refreshToken, err := u.JwtService.Generate(existingUser,tokenId.String())

		if err != nil {
			return nil, err
		}
		existingUser.IsVerified = true
		err = u.UserRepository.SaveUserUpdate(existingUser)
		if err != nil {
			return nil, err
		}
		err = u.CacheRepository.Set(existingUser.UserID.String() + tokenId.String(), refreshToken, 72 * time.Hour)
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
			TwoFactorAuth: existingUser.TwoFactorAuth,
		}
		return &newUser, nil
	}
	user.Role = "user"
	user.UserID = uuid.New()
	tokeId := uuid.New()
	accessToken, refreshToken, err := u.JwtService.Generate(user,tokeId.String())
	if err != nil {
		return nil, err
	}
	err = u.CacheRepository.Set(user.UserID.String() + tokeId.String(), refreshToken, 72 * time.Hour)
	if err != nil {
		return nil, err
	}
	userModel, err := u.UserRepository.CreateUser(user)
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
		AccessToken: accessToken,
		RefreshToken: refreshToken,
		TwoFactorAuth: userModel.TwoFactorAuth,
	}
	return &response, nil
}

// verify user email
func (u *UserAuth) VerifyEmail(Token string) *errors.CustomError {
	token, err := u.JwtService.ValidateVerificationToken(Token)
	if err != nil {
		return err
	}
	if token == nil || !token.Valid {
		return errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	email, ok := claims["email"].(string)
	if !ok {
		return errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	tokenResult,err := u.CacheRepository.Get(email + "verification_token")
	if err != nil {
		return err
	}

	if tokenResult != Token {
		return errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	user, err := u.UserRepository.GetUserByEmail(email)
	if err != nil {
		return err 
	}
	user.IsVerified = true
	err = u.UserRepository.SaveUserUpdate(user)
	if err != nil {
		return err
	}
	return nil
}

// Resend verification email
func (u *UserAuth) ResendVerificationEmail(email string) *errors.CustomError {
	user, err := u.UserRepository.GetUserByEmail(email)
	if err != nil {
		return err
	}
	if user.IsVerified {
		return errors.NewCustomError("User already verified", http.StatusConflict)
	}
	token, err := u.JwtService.GenerateVerificationToken(user)
	if err != nil {
		return err
	}
	err = u.CacheRepository.Set(user.Email + "verification_token", token, 30*time.Minute)
	if err != nil {
		return err
	}
	// Get email body
	emailBody,errs := u.EmailService.GetOTPEmailBody("localhost:8080/api/auth/user/verify_email?verification_token=" + token,"email_verification.html")
	if errs != nil {
		return errors.NewCustomError(errs.Error(), http.StatusInternalServerError)
	}
	// Send verification email
	e := u.EmailService.SendEmail(user.Email, "Email Verification", emailBody,"go_auth@gmail.com")
	if e != nil {
		return errors.NewCustomError(e.Error(), http.StatusInternalServerError)
	}
	return nil
}


//Forgot Password
func (u *UserAuth) ForgotPassword(email *dto.EmailDTO) *errors.CustomError {
	user, err := u.UserRepository.GetUserByEmail(email.Email)
	if err != nil {
		return err
	}
	token, err := u.JwtService.GeneratePasswordResetToken(user)
	if err != nil {
		return err
	}

	// Get email body
	err = u.CacheRepository.Set(user.Email + "password_reset_token", token, 30*time.Minute)
	if err != nil {
		return err
	}
	emailBody, errs := u.EmailService.GetOTPEmailBody("localhost:8080/api/auth/user/reset_password?reset_token=" + token,"password_verification.html")
	if errs != nil {
		return errors.NewCustomError(errs.Error(), http.StatusInternalServerError)
	}

	// Send verification email
	e := u.EmailService.SendEmail(user.Email, "Password Reset", emailBody,"noreplay@gmail.com")
	if e != nil {
		return errors.NewCustomError(e.Error(), http.StatusInternalServerError)
	}

	return nil


}

//reset Password
func (u *UserAuth) ResetPassword(password string, token string) *errors.CustomError {
	Token, err := u.JwtService.ValidePasswordResetToken(token)
	if err != nil {
		return err
	}
	if Token == nil || !Token.Valid {
		return errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	claims, ok := Token.Claims.(jwt.MapClaims)
	if !ok || !Token.Valid {
		return errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	id, ok := claims["user_id"].(string)
	if !ok {
		return errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	email, ok := claims["email"].(string)
	if !ok {
		return errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	user, err := u.UserRepository.GetUserById(id)
	if err != nil {
		return err
	}
	tokenResult, err := u.CacheRepository.Get(email + "password_reset_token")
	if err != nil {
		return err
	}
	if tokenResult != token {
		return errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	password , err = u.PwdService.HashPassword(password)
	if err != nil {
		return err
	}
	user.Password = password
	err = u.UserRepository.SaveUserUpdate(user)
	if err != nil {
		return err
	}
	return nil
}

func (u *UserAuth) ValidateToken(user_id string) (*dto.UserResponseDTO, *errors.CustomError) {

	user, err := u.UserRepository.GetUserById(user_id)
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
		TwoFactorAuth: user.TwoFactorAuth,
	}
	return &response, nil
}

func (u *UserAuth) CheckToken(token string) *errors.CustomError {
	tokenString ,err := u.JwtService.ValidateRefreshToken(token)
	if err != nil {
		return err
	}
	if tokenString == nil || !tokenString.Valid {
		return errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	claims, ok := tokenString.Claims.(jwt.MapClaims)
	if !ok {
		return errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	tokenId, ok := claims["token_id"].(string)
	if !ok {
		return errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	user_id, ok := claims["user_id"].(string)
	if !ok {
		return errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	result, err := u.CacheRepository.Get(user_id + tokenId)
	if err != nil {
		return err
	}
	tokenString, err = u.JwtService.ValidateRefreshToken(result)
	if err != nil {
		return err
	}
	
	if tokenString == nil || !tokenString.Valid {
		return errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	if result != token {
		return errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	return nil
}


//2FA verification
func (u *UserAuth) TwoFactorAuthenticationVerification(email string,otpCode string, otpToken string) (*dto.UserResponseDTO,*errors.CustomError) {
	// verify otpCode

	OTPToken, err := u.JwtService.ValidateOtpToken(otpToken)
	if err != nil {
		return nil, err
	}
	if OTPToken == nil || !OTPToken.Valid {
		return nil,errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	claims, ok := OTPToken.Claims.(jwt.MapClaims)
	if !ok || !OTPToken.Valid {
		return nil, errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	tokenEmail, ok := claims["user_email"].(string)
	if !ok {
		return nil, errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	OtpTokenResult, err := u.CacheRepository.Get(tokenEmail + "otp_token")
	if err != nil {
		return  nil, err
	}
	if OtpTokenResult != otpToken {
		return nil,errors.NewCustomError("Invalid OTP code", http.StatusUnauthorized)
	}
	result, err := u.UserRepository.GetUserByEmail(tokenEmail)
	if err != nil {
		return  nil, err
	}
	valid := totp.Validate(otpCode, u.TwoFactorSecretKey)
	if !valid {
		return nil,errors.NewCustomError("Invalid OTP code", http.StatusUnauthorized)
	}
	Otpresult, err := u.CacheRepository.Get(tokenEmail + "otp_code")
	if err != nil {
		return  nil, err
	}
	if Otpresult != otpCode {
		return nil,errors.NewCustomError("Invalid OTP code", http.StatusUnauthorized)
	}
	tokenId := uuid.New()
	accessToken, refreshToken, err := u.JwtService.Generate(result,tokenId.String())
	if err != nil {
		return nil, err
	}
	err = u.CacheRepository.Set(result.UserID.String() + tokenId.String(), refreshToken, 72 *time.Hour)
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
		TwoFactorAuth: result.TwoFactorAuth,
	}

	return &token, nil
}

// enable 2FA
func (u *UserAuth) EnableTwoFactorAuthentication(email string) *errors.CustomError {
	result, err := u.UserRepository.GetUserByEmail(email)
	if err != nil {
		return err
	}
	result.TwoFactorAuth = !result.TwoFactorAuth
	err = u.UserRepository.SaveUserUpdate(result)
	if err != nil {
		return err
	}
	return nil
}

// Resend otp code
func (u *UserAuth) ResendOTPCode(email string,otpToken string) *errors.CustomError {
	OTPToken, err := u.JwtService.ValidateOtpToken(otpToken)
	if err != nil {
		return err
	}
	claims, ok := OTPToken.Claims.(jwt.MapClaims)
	if !ok || !OTPToken.Valid {
		return errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	tokenEmail, ok := claims["user_email"].(string)
	if !ok {
		return errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	if tokenEmail != email {
		return errors.NewCustomError("Invalid token", http.StatusUnauthorized)
	}
	result, err := u.UserRepository.GetUserByEmail(tokenEmail)
	if err != nil {
		return err

	}
	SecretKey := u.TwoFactorSecretKey
	otpCode, errs := totp.GenerateCode(SecretKey, time.Now())
	if errs != nil {
		return errors.NewCustomError(errs.Error(), http.StatusInternalServerError)
	}
	err = u.CacheRepository.Set(result.Email + "otp_code",otpCode, 15 * time.Minute)
	if err != nil {
		return err
	}
	emailBody,errs := u.EmailService.GetOTPEmailBody(otpCode,"otp_verification.html")
	if errs != nil {
		return errors.NewCustomError("Error getting email body", http.StatusInternalServerError)
	}

	e := u.EmailService.SendEmail(result.Email, "Two Factor Authentication", emailBody, "go_auth@gmail.com")
	if e != nil {
		return errors.NewCustomError("Error sending email", http.StatusInternalServerError)
	}
	return nil

}
