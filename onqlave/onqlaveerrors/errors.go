package onqlaveerrors

import (
	"errors"
	"fmt"
)

// ErrorCodes - Enum defines the list of error codes/categorization of errors in Skyflow.
type ErrorCodes string

// Defining the values of Error code Enum
const (
	// Server - Represents server side error
	Server ErrorCodes = "Server"
	// InvalidInput - Input passed was not invalid format
	InvalidInput = "InvalidInput"
	SdkErrorCode = "400"
)

// OnqlaveError - The Error Object for Onqlave APIs. Contains :
// 1. code - Represents the type of error
// 2. message - The message contained in the error
// 3. originalError - The original error (if any) which resulted in this error
type OnqlaveError struct {
	originalError error
	code          ErrorCodes
	message       string
}

// NewOnqlaveErrorf - Creates a new Onqlave Error Object with Parameter Substitution
func NewOnqlaveErrorf(code ErrorCodes, format string, a ...interface{}) *OnqlaveError {
	return NewOnqlaveError(code, fmt.Sprintf(format, a...))
}

// NewOnqlaveError - Creates a new Onqlave Error Object with given message
func NewOnqlaveError(code ErrorCodes, message string) *OnqlaveError {
	return &OnqlaveError{code: code, message: message, originalError: errors.New("<nil>")}
}

// NewOnqlaveErrorWrap - Creates a new Onqlave Error Object using the given error
func NewOnqlaveErrorWrap(code ErrorCodes, err error, message string) *OnqlaveError {
	return &OnqlaveError{code: code, message: message, originalError: err}
}

// NewOnqlaveErrorWrapf - Creates a new Onqlave Error Object using the given error & with Parameter Substitution
func NewOnqlaveErrorWrapf(code ErrorCodes, err error, format string, a ...interface{}) *OnqlaveError {
	return NewOnqlaveErrorWrap(code, err, fmt.Sprintf(format, a...))
}

// GetOriginalError - Returns the underlying error (if any)
func (se *OnqlaveError) GetOriginalError() error {
	return se.originalError
}

// Error - Uses the Underlying go's error for providing Error() interface impl.
func (se *OnqlaveError) Error() string {
	if se.originalError != nil {
		return fmt.Sprintf("Message: %s, Original Error (if any): %s", se.message, se.originalError.Error())
	} else {
		return fmt.Sprintf("Message: %s, Original Error <nil>", se.message)
	}
}

func (se *OnqlaveError) GetMessage() string {
	return fmt.Sprintf("Message: %s", se.message)
}

func (se *OnqlaveError) GetCode() string {
	return fmt.Sprintf("Code: %s", se.code)
}
