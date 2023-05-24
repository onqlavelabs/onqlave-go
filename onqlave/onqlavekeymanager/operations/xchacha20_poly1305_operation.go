package operations

import "github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager/types"

const (
	XchaCha20Poly1305KeyVersion = 0
)

// NewXChaCha20Poly1305KeyOperation ChaCha20Poly1305KeyOperation is a KeyOperation that generates a CHACHA20_POLY1305 key.
func NewXChaCha20Poly1305KeyOperation(factory types.KeyFactory) types.KeyOperation {
	format := &XChaChaKeyFormat{
		KeySize: 32,
	}
	return &xChaCha20Poly1305KeyOperation{
		format:  format,
		factory: factory,
	}
}

type xChaCha20Poly1305KeyOperation struct {
	factory types.KeyFactory
	format  *XChaChaKeyFormat
}

type XChaChaKeyFormat struct {
	KeySize uint32
	Version uint32
}

func (f *XChaChaKeyFormat) Size() uint32 {
	return f.KeySize
}

func (operation *xChaCha20Poly1305KeyOperation) GetFormat() types.KeyFormat {
	return operation.format
}

func (operation *xChaCha20Poly1305KeyOperation) GetFactory() types.KeyFactory {
	return operation.factory
}
