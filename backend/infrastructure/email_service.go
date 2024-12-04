package infrastructure

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	gomail "gopkg.in/mail.v2"
)

// EmailService is a struct that holds the email service
type EmailService struct {
	dialer *gomail.Dialer
}

// NewEmailService creates a new email service
func NewEmailService(dialer *gomail.Dialer) *EmailService {
	return &EmailService{
		dialer: dialer,
	}
}


// SendEmail sends an email to the user
func (emailService *EmailService) SendEmail(email string, subject string, body string,from string) error {
	message := gomail.NewMessage()

	// Set email headers
	message.SetHeader("From", from)
	message.SetHeader("To", email)
	message.SetHeader("Subject", subject)

	// Set email body
	message.SetBody("text/html", body)

	// Send the email
	if err := emailService.dialer.DialAndSend(message); err != nil {
		return err
	}
	return nil

}

func (emailService *EmailService) GetOTPEmailBody(otpCode string,file_name string) (string, error) {
	dir, err := os.Getwd() // Get the current working directory
	if err != nil {
		panic(err) // Handle error appropriately in production
	}
	templatePath := filepath.Join(dir, "templates", file_name)

    content, err := os.ReadFile(templatePath) 
    if err != nil {
        return "", err
    }
    body := string(content)
    return strings.Replace(body, "{{TOKEN_LINK}}", otpCode, -1), nil
}

func (emailServie *EmailService) GenerateOTP(length int) (string, error) {
	var otp string
	for i := 0; i < length; i++ {
		// Generate a random digit between 0 and 9
		num, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", fmt.Errorf("error generating OTP: %v", err)
		}
		otp += num.String()
	}
	return otp, nil
}