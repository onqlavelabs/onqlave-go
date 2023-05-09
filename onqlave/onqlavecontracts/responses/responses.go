package responses

import "github.com/onqlavelabs/onqlave-go/onqlave/onqlavecontracts"

type BaseErrorResponse struct {
	Error Error `json:"error"`
}

type Error struct {
	Status        string        `json:"status" yaml:"status"`                 // Status represent string value of code
	Message       string        `json:"message" yaml:"message"`               // Message represent detail message
	CorrelationID string        `json:"correlation_id" yaml:"correlation_id"` // The RequestId that's also set in the header
	Details       []interface{} `json:"details" yaml:"details"`               // Details is a list of details in any types in string
	Code          int           `json:"code" yaml:"code"`                     // Code represent codes in response
}

type DecryptionOpenResponse struct {
	WK            onqlavecontracts.WrappingKey             `json:"wrapping_key" validate:"required"`
	SecurityModel onqlavecontracts.EncryptionSecurityModel `json:"security_model"`
	DK            onqlavecontracts.DataDecryptionKey       `json:"data_key" validate:"required"`
	BaseErrorResponse
}

type EncryptionOpenResponse struct {
	WK            onqlavecontracts.WrappingKey             `json:"wrapping_key" validate:"required"`
	DK            onqlavecontracts.DataEncryptionKey       `json:"data_key" validate:"required"`
	SecurityModel onqlavecontracts.EncryptionSecurityModel `json:"security_model"`
	BaseErrorResponse
	MaxUses uint `json:"max_uses" validate:"required"`
}
