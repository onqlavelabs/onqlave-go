package operations

import (
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager/types"
)

const (
	AESGCMKeyVersion = 0
)

// AES128GCMKeyOperation is a KeyOperation that is used to generate an AES-GCM key with the following parameters:
//   - Key size: 16 bytes
func NewAES128GCMKeyOperation(factory types.KeyFactory) types.KeyOperation {
	format := &AesGcmKeyFormat{
		KeySize: 16,
	}
	return &aes128GCMKeyOperation{
		format:  format,
		factory: factory,
	}
}

type aes128GCMKeyOperation struct {
	factory types.KeyFactory
	format  *AesGcmKeyFormat
}

// Only allowing IV size in bytes = 12 and tag size in bytes = 16
// Thus, accept no params.
type AesGcmKeyFormat struct {
	KeySize uint32
	Version uint32
}

func (f *AesGcmKeyFormat) Size() uint32 {
	return f.KeySize
}

func (operation *aes128GCMKeyOperation) GetFormat() types.KeyFormat {
	return operation.format
}

func (operation *aes128GCMKeyOperation) GetFactory() types.KeyFactory {
	return operation.factory
}
