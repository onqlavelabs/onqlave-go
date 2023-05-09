package operations

import "github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager/types"

const (
	RSASSAPKCS1KeyVersion = 0
)

func NewRSASSAPKCS1SHA2562048KeyOperation(factory types.WrappingKeyFactory) types.WrappingKeyOperation {
	format := &RsaSsaPkcs1KeyFormat{
		Version: RSASSAPKCS1KeyVersion,
		Hash:    types.HashTypeSHA256,
	}
	return &rsaSSAPKCS1SHA2562048KeyOperation{
		format:  format,
		factory: factory,
	}
}

type rsaSSAPKCS1SHA2562048KeyOperation struct {
	factory types.WrappingKeyFactory
	format  *RsaSsaPkcs1KeyFormat
}

type RsaSsaPkcs1KeyFormat struct {
	Version uint32
	Hash    types.HashType
}

func (f *RsaSsaPkcs1KeyFormat) Size() uint32 {
	return 0
}

func (operation *rsaSSAPKCS1SHA2562048KeyOperation) GetFormat() types.KeyFormat {
	return operation.format
}

func (operation *rsaSSAPKCS1SHA2562048KeyOperation) GetFactory() types.WrappingKeyFactory {
	return operation.factory
}
