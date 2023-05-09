package requests

import "encoding/json"

type EncryptionOpenRequest struct {
}

type DecryptionOpenRequest struct {
	EDK string `json:"encrypted_data_key" validate:"required,max=1500"`
}

type OnqlaveRequest interface {
	GetContent() ([]byte, error)
}

func (r *EncryptionOpenRequest) GetContent() ([]byte, error) {
	return json.Marshal(r)
}

func (r *DecryptionOpenRequest) GetContent() ([]byte, error) {
	return json.Marshal(r)
}
