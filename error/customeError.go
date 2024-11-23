package errors

// CustomError represents an error with a message and a status code
type CustomError struct {
    Message    string
    StatusCode int
}
// Error implements error.
func (c *CustomError) Error() string {
	return c.Message
}

func NewCustomError(message string, statusCode int) *CustomError {
    return &CustomError{
        Message:    message,
        StatusCode: statusCode,
    }
}
