package operations

import (
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager/types"
)

// NewAES256GCMKeyOperation AES256GCMKeyOperation is a KeyOperation that is used to generate an AES-GCM key with the following parameters:
//   - Key size: 32 bytes
func NewAES256GCMKeyOperation(factory types.KeyFactory) types.KeyOperation {
	format := &AesGcmKeyFormat{
		KeySize: 32,
	}
	return &aes256GCMKeyOperation{
		format:  format,
		factory: factory,
	}
}

type aes256GCMKeyOperation struct {
	factory types.KeyFactory
	format  *AesGcmKeyFormat
}

func (operation *aes256GCMKeyOperation) GetFormat() types.KeyFormat {
	return operation.format
}

func (operation *aes256GCMKeyOperation) GetFactory() types.KeyFactory {
	return operation.factory
}
