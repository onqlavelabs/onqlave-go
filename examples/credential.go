package examples

import (
	"encoding/json"
	"io"
	"os"
)

type Credential struct {
	Arx        string `json:"arx_url"`
	AccessKey  string `json:"access_key"`
	SigningKey string `json:"server_signing_key"`
	SecretKey  string `json:"server_secret_key"`
}

type Credentials struct {
	Credentials []Credential `json:"credentials"`
}

func LoadCredentials(credentialFile string) ([]Credential, error) {
	jsonFile, err := os.Open(credentialFile)
	if err != nil {
		return nil, err
	}
	var credentials Credentials
	jsonBytes, err := io.ReadAll(jsonFile)
	if err != nil {
		return nil, err
	}
	json.Unmarshal(jsonBytes, &credentials)
	return credentials.Credentials, err
}
