package factories

import (
	"fmt"

	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager/keys"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager/operations"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager/primitives"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager/services"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager/types"
)

type aesGcmKeyFactory struct {
	idService     services.IDService
	randomService services.CPRNGService
}

func NewAEADGCMKeyFactory(idService services.IDService, randomService services.CPRNGService) types.KeyFactory {
	return &aesGcmKeyFactory{idService: idService, randomService: randomService}
}

func (factory *aesGcmKeyFactory) NewKey(operation types.KeyOperation) (types.Key, error) {
	format := operation.GetFormat()
	if err := factory.validateKeyFormat(format); err != nil {
		return nil, fmt.Errorf("aesGcmKeyFactory: invalid key format: %s", err)
	}
	keyValue := factory.randomService.GetRandomBytes(format.Size())
	return keys.NewAesGcmKey(factory.idService.NewKeyID(), operation, &keys.AesGcmKeyData{
		Value:           keyValue,
		KeyMaterialType: types.KeyMaterialSYMMETRIC,
		Version:         0,
	}), nil
}

func (factory *aesGcmKeyFactory) NewKeyFromData(operation types.KeyOperation, keyData []byte) (types.Key, error) {
	format := operation.GetFormat()
	if err := factory.validateKeyFormat(format); err != nil {
		return nil, fmt.Errorf("aesGcmKeyFactory: invalid key format: %s", err)
	}
	return keys.NewAesGcmKey(factory.idService.NewKeyID(), operation, &keys.AesGcmKeyData{
		Value:           keyData,
		KeyMaterialType: types.KeyMaterialSYMMETRIC,
		Version:         0,
	}), nil
}

func (factory *aesGcmKeyFactory) Primitive(key types.Key) (types.AEAD, error) {
	if err := factory.validateKey(key); err != nil {
		return nil, err
	}
	ret, err := primitives.NewAESGCMAEAD(key, factory.randomService)
	if err != nil {
		return nil, fmt.Errorf("aesGcmKeyFactory: cannot create new primitive: %s", err)
	}
	return ret, nil
}

// validateKey validates the given AESGCMKey.
func (factory *aesGcmKeyFactory) validateKey(key types.Key) error {
	keyData := key.Data()
	err := factory.ValidateKeyVersion(keyData.GetVersion(), operations.AESGCMKeyVersion)
	if err != nil {
		return fmt.Errorf("aesGcmKeyFactory: invalid key version: %s", err)
	}
	value, err := keyData.GetValue()
	if err != nil {
		return fmt.Errorf("aesGcmKeyFactory: invalid key version: %s", err)
	}
	keySize := uint32(len(value))
	if err := primitives.ValidateAESKeySize(keySize); err != nil {
		return fmt.Errorf("aesGcmKeyFactory: invalid key size: %s", err)
	}
	return nil
}

// validateKeyFormat validates the given AESGCMKeyFormat.
func (factory *aesGcmKeyFactory) validateKeyFormat(format types.KeyFormat) error {
	if err := primitives.ValidateAESKeySize(format.Size()); err != nil {
		return fmt.Errorf("aesGcmKeyFactory: invalid key format: %s", err)
	}
	return nil
}

func (factory *aesGcmKeyFactory) ValidateKeyVersion(version, maxExpected uint32) error {
	if version > maxExpected {
		return fmt.Errorf("key has version %v; only keys with version in range [0..%v] are supported",
			version, maxExpected)
	}
	return nil
}
