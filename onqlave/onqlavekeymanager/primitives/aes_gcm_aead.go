package primitives

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"

	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager/services"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager/types"
)

const (
	// AESGCMIVSize is the acceptable IV size defined by RFC 5116.
	AESGCMIVSize = 12
	// AESGCMTagSize is the acceptable tag size defined by RFC 5116.
	AESGCMTagSize = 16
)

// AESGCMAEAD is an implementation of AEAD interface.
type AESGCMAEAD struct {
	randomService services.CPRNGService
	key           []byte
	prependIV     bool
}

// Assert that AESGCMAEAD implements the AEAD interface.
var _ types.AEAD = (*AESGCMAEAD)(nil)

// NewAESGCM returns an AESGCMAEAD instance, where key is the AES key with length
// 16 bytes (AES-128) or 32 bytes (AES-256).
func NewAESGCMAEAD(key types.Key, randomService services.CPRNGService) (types.AEAD, error) {
	keyData := key.Data()
	keyValue, err := keyData.GetValue()
	if err != nil {
		return nil, err
	}
	keySize := uint32(len(keyValue))
	if err := ValidateAESKeySize(keySize); err != nil {
		return nil, fmt.Errorf("invalid AES key size: %s", err)
	}
	return &AESGCMAEAD{randomService: randomService, key: keyValue, prependIV: true}, err
}

// Encrypt encrypts plaintext with iv as the initialization vector and
// associatedData as associated data.
//
// If prependIV is true, the returned ciphertext contains both the IV used for
// encryption and the actual ciphertext.
// If false, the returned ciphertext contains only the actual ciphertext.
//
// Note: The crypto library's AES-GCM implementation always returns the
// ciphertext with an AESGCMTagSize (16-byte) tag.
func (a *AESGCMAEAD) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	iv := a.randomService.GetRandomBytes(AESGCMIVSize)
	if got, want := len(iv), AESGCMIVSize; got != want {
		return nil, fmt.Errorf("unexpected IV size: got %d, want %d", got, want)
	}
	// Seal() checks plaintext length, but this duplicated check avoids panic.
	var maxPlaintextSize uint64 = maxIntPlaintextSize
	if maxIntPlaintextSize > aesGCMMaxPlaintextSize {
		maxPlaintextSize = aesGCMMaxPlaintextSize
	}
	if uint64(len(plaintext)) > maxPlaintextSize {
		return nil, fmt.Errorf("plaintext too long: got %d", len(plaintext))
	}

	cipher, err := a.newCipher()
	if err != nil {
		return nil, err
	}
	ciphertext := cipher.Seal(nil, iv, plaintext, associatedData)

	if a.prependIV {
		return append(iv, ciphertext...), nil
	}
	return ciphertext, nil
}

// Decrypt decrypts ciphertext with iv as the initialization vector and
// associatedData as associated data.
//
// If prependIV is true, the iv argument and the first AESGCMIVSize bytes of
// ciphertext must be equal. The ciphertext argument is as follows:
//
//	| iv | actual ciphertext | tag |
//
// If false, the ciphertext argument is as follows:
//
//	| actual ciphertext | tag |
func (a *AESGCMAEAD) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	if len(ciphertext) < AESGCMIVSize {
		return nil, fmt.Errorf("ciphertext with size %d is too short", len(ciphertext))
	}
	iv := ciphertext[:AESGCMIVSize]
	if len(iv) != AESGCMIVSize {
		return nil, fmt.Errorf("unexpected IV size: got %d, want %d", len(iv), AESGCMIVSize)
	}

	var actualCiphertext []byte
	if a.prependIV {
		if len(ciphertext) < minPrependIVCiphertextSize {
			return nil, fmt.Errorf("ciphertext too short: got %d, want >= %d", len(ciphertext), minPrependIVCiphertextSize)
		}
		if !bytes.Equal(iv, ciphertext[:AESGCMIVSize]) {
			return nil, fmt.Errorf("unequal IVs: iv argument %x, ct prefix %x", iv, ciphertext[:AESGCMIVSize])
		}
		actualCiphertext = ciphertext[AESGCMIVSize:]
	} else {
		if len(ciphertext) < minNoIVCiphertextSize {
			return nil, fmt.Errorf("ciphertext too short: got %d, want >= %d", len(ciphertext), minNoIVCiphertextSize)
		}
		actualCiphertext = ciphertext
	}

	cipher, err := a.newCipher()
	if err != nil {
		return nil, err
	}
	plaintext, err := cipher.Open(nil, iv, actualCiphertext, associatedData)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

const (
	// aesGCMMaxPlaintextSize is the maximum plaintext size defined by RFC 5116.
	aesGCMMaxPlaintextSize = (1 << 36) - 31

	intSize             = 32 << (^uint(0) >> 63) // 32 or 64
	maxInt              = 1<<(intSize-1) - 1
	maxIntPlaintextSize = maxInt - AESGCMIVSize - AESGCMTagSize

	minNoIVCiphertextSize      = AESGCMTagSize
	minPrependIVCiphertextSize = AESGCMIVSize + AESGCMTagSize
)

// ValidateAESKeySize checks if the given key size is a valid AES key size.
func ValidateAESKeySize(sizeInBytes uint32) error {
	switch sizeInBytes {
	case 16, 32:
		return nil
	default:
		return fmt.Errorf("invalid AES key size; want 16 or 32, got %d", sizeInBytes)
	}
}

// newCipher creates a new AES-GCM cipher using the given key and the crypto
// library.
func (a *AESGCMAEAD) newCipher() (cipher.AEAD, error) {
	aesCipher, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, errors.New("failed to initialize cipher")
	}
	ret, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, errors.New("failed to initialize cipher")
	}
	return ret, nil
}
