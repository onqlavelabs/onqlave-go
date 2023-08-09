package onqlaveencryption

import (
	"os"
	"testing"

	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavecredentials"
	"gopkg.in/go-playground/assert.v1"
)

func initEncryptionService(accessKey, signingKey, secretKey, arxURL string) *Encryption {
	arxOption := WithArx(arxURL)
	credentialOption := WithCredential(onqlavecredentials.Credential{
		AccessKey:  accessKey,
		SigningKey: signingKey,
		SecretKey:  secretKey,
	})

	return NewEncryption(arxOption, credentialOption)
}

func TestAES128EncryptMethod(t *testing.T) {
	accessKey := os.Getenv("AES_128_ACCESS_KEY")
	signingKey := os.Getenv("AES_128_SIGNING_KEY")
	secretKey := os.Getenv("AES_128_SECRET_KEY")
	arxURL := os.Getenv("AES_128_ARX_URL")
	if accessKey == "" || signingKey == "" || secretKey == "" || arxURL == "" {
		t.Log("env is not set")
		t.SkipNow()
	}

	service := initEncryptionService(accessKey, signingKey, secretKey, arxURL)

	plainText := "this is a plain text string"
	associatedData := "associated data"
	cipherData, err := service.Encrypt([]byte(plainText), []byte(associatedData))
	assert.Equal(t, err, nil)

	decryptedData, err := service.Decrypt(cipherData, []byte(associatedData))
	assert.Equal(t, err, nil)
	assert.Equal(t, plainText, string(decryptedData))
}

func TestAES256EncryptionMethod(t *testing.T) {
	accessKey := os.Getenv("AES_256_ACCESS_KEY")
	signingKey := os.Getenv("AES_256_SIGNING_KEY")
	secretKey := os.Getenv("AES_256_SECRET_KEY")
	arxURL := os.Getenv("AES_256_ARX_URL")

	if accessKey == "" || signingKey == "" || secretKey == "" || arxURL == "" {
		t.Log("env is not set")
		t.SkipNow()
	}

	service := initEncryptionService(accessKey, signingKey, secretKey, arxURL)

	plainText := "this is a plain text string"
	associatedData := "associated data"

	cipherData, err := service.Encrypt([]byte(plainText), []byte(associatedData))
	assert.Equal(t, err, nil)

	decryptedData, err := service.Decrypt(cipherData, []byte(associatedData))
	assert.Equal(t, err, nil)
	assert.Equal(t, plainText, string(decryptedData))
}

func TestXChaCha20Poly1305(t *testing.T) {
	accessKey := os.Getenv("XCHACHA_ACCESS_KEY")
	signingKey := os.Getenv("XCHACHA_SIGNING_KEY")
	secretKey := os.Getenv("XCHACHA_SECRET_KEY")
	arxURL := os.Getenv("XCHACHA_ARX_URL")

	if accessKey == "" || signingKey == "" || secretKey == "" || arxURL == "" {
		t.Log("env is not set")
		t.SkipNow()
	}

	service := initEncryptionService(accessKey, signingKey, secretKey, arxURL)

	plainText := "this is a plain text string"
	associatedData := "associated data"
	cipherData, err := service.Encrypt([]byte(plainText), []byte(associatedData))
	assert.Equal(t, err, nil)

	decryptedData, err := service.Decrypt(cipherData, []byte(associatedData))
	assert.Equal(t, err, nil)
	assert.Equal(t, plainText, string(decryptedData))
}
