package factories

import (
	"fmt"

	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager/keys"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager/operations"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager/primitives"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager/services"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager/types"
	"golang.org/x/crypto/chacha20poly1305"
)

type xChaCha20Poly1305KeyFactory struct {
	idService     services.IDService
	randomService services.CPRNGService
}

func NewXChaCha20Poly1305KeyFactory(idService services.IDService, randomService services.CPRNGService) types.KeyFactory {
	return &xChaCha20Poly1305KeyFactory{idService: idService, randomService: randomService}
}

func (factory *xChaCha20Poly1305KeyFactory) NewKey(operation types.KeyOperation) (types.Key, error) {
	format := operation.GetFormat()
	if err := factory.validateKeyFormat(format); err != nil {
		return nil, fmt.Errorf("aes_gcm_key_manager: invalid key format: %s", err)
	}
	keyValue := factory.randomService.GetRandomBytes(format.Size())
	return keys.NewXChaCha20Poly1305Key(factory.idService.NewKeyID(), operation, &keys.XChaCha20Poly1305KeyData{
		Value:           keyValue,
		KeyMaterialType: types.KeyMaterialSYMMETRIC,
		Version:         0,
	}), nil
}

func (factory *xChaCha20Poly1305KeyFactory) NewKeyFromData(operation types.KeyOperation, keyData []byte) (types.Key, error) {
	format := operation.GetFormat()
	if err := factory.validateKeyFormat(format); err != nil {
		return nil, fmt.Errorf("aes_gcm_key_manager: invalid key format: %s", err)
	}
	return keys.NewXChaCha20Poly1305Key(factory.idService.NewKeyID(), operation, &keys.XChaCha20Poly1305KeyData{
		Value:           keyData,
		KeyMaterialType: types.KeyMaterialSYMMETRIC,
		Version:         0,
	}), nil
}

func (factory *xChaCha20Poly1305KeyFactory) Primitive(key types.Key) (types.AEAD, error) {
	if err := factory.validateKey(key); err != nil {
		return nil, err
	}
	ret, err := primitives.NewXChaCha20Poly1305AEAD(key, factory.randomService)
	if err != nil {
		return nil, fmt.Errorf("aes_gcm_key_manager: cannot create new primitive: %s", err)
	}
	return ret, nil
}

// validateKey validates the given XChaCha20Poly1305Key.
func (factory *xChaCha20Poly1305KeyFactory) validateKey(key types.Key) error {
	err := factory.validateKeyVersion(key.Data().GetVersion(), operations.XchaCha20Poly1305KeyVersion)
	if err != nil {
		return fmt.Errorf("xchacha_poly1305_key_manager: %s", err)
	}
	value, err := key.Data().GetValue()
	if err != nil {
		return fmt.Errorf("xchacha_poly1305_key_manager: %s", err)
	}
	keySize := uint32(len(value))
	if err := factory.validateXChaChaKeySize(keySize); err != nil {
		return fmt.Errorf("xchacha_poly1305_key_manager: %s", err)
	}
	return nil
}

// validateKeyFormat validates the given XChaChaKeyFormat.
func (factory *xChaCha20Poly1305KeyFactory) validateKeyFormat(format types.KeyFormat) error {
	if err := factory.validateXChaChaKeySize(format.Size()); err != nil {
		return fmt.Errorf("aes_gcm_key_manager: %s", err)
	}
	return nil
}

func (factory *xChaCha20Poly1305KeyFactory) validateKeyVersion(version, maxExpected uint32) error {
	if version > maxExpected {
		return fmt.Errorf("key has version %v; only keys with version in range [0..%v] are supported",
			version, maxExpected)
	}
	return nil
}

// ValidateXChaChaKeySize checks if the given key size is a valid AES key size.
func (factory *xChaCha20Poly1305KeyFactory) validateXChaChaKeySize(sizeInBytes uint32) error {
	if sizeInBytes != chacha20poly1305.KeySize {
		return fmt.Errorf("invalid XChaCha key size; want %d , got %d", chacha20poly1305.KeySize, sizeInBytes)
	}
	return nil
}
