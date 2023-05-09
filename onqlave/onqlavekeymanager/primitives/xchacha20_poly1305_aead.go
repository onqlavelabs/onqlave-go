package primitives

import (
	"fmt"

	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager/services"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager/types"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	poly1305TagSize = 16
)

// XChaCha20Poly1305AEAD is an implementation of AEAD interface.
type XChaCha20Poly1305AEAD struct {
	key           types.Key
	randomService services.CPRNGService
}

// Assert that XChaCha20Poly1305AEAD implements the AEAD interface.
var _ types.AEAD = (*XChaCha20Poly1305AEAD)(nil)

// NewXChaCha20Poly1305AEAD returns an XChaCha20Poly1305AEAD instance.
// The key argument should be a 32-bytes key.
func NewXChaCha20Poly1305AEAD(key types.Key, randomService services.CPRNGService) (types.AEAD, error) {
	return &XChaCha20Poly1305AEAD{key: key, randomService: randomService}, nil
}

// Encrypt encrypts plaintext with associatedData.
// The resulting ciphertext consists of two parts:
// (1) the nonce used for encryption and (2) the actual ciphertext.
func (a *XChaCha20Poly1305AEAD) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	if len(plaintext) > maxInt-chacha20poly1305.NonceSizeX-poly1305TagSize {
		return nil, fmt.Errorf("xchacha20poly1305: plaintext too long")
	}
	keyData := a.key.Data()
	keyValue, err := keyData.GetValue()
	if err != nil {
		return nil, err
	}
	c, err := chacha20poly1305.NewX(keyValue)
	if err != nil {
		return nil, err
	}

	n := a.newNonce()
	ct := c.Seal(nil, n, plaintext, associatedData)
	return append(n, ct...), nil
}

// Decrypt decrypts ciphertext with associatedData.
func (a *XChaCha20Poly1305AEAD) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	if len(ciphertext) < chacha20poly1305.NonceSizeX+poly1305TagSize {
		return nil, fmt.Errorf("xchacha20poly1305: ciphertext too short")
	}

	keyData := a.key.Data()
	keyValue, err := keyData.GetValue()
	if err != nil {
		return nil, err
	}
	c, err := chacha20poly1305.NewX(keyValue)
	if err != nil {
		return nil, err
	}

	n := ciphertext[:chacha20poly1305.NonceSizeX]
	pt, err := c.Open(nil, n, ciphertext[chacha20poly1305.NonceSizeX:], associatedData)
	if err != nil {
		return nil, fmt.Errorf("XChaCha20Poly1305.Decrypt: %s", err)
	}
	return pt, nil
}

// newNonce creates a new nonce for encryption.
func (a *XChaCha20Poly1305AEAD) newNonce() []byte {
	return a.randomService.GetRandomBytes(chacha20poly1305.NonceSizeX)
}
