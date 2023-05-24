package keys

import "github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager/types"

type XChaCha20Poly1305Key struct {
	operation types.KeyOperation
	data      *XChaCha20Poly1305KeyData
	keyID     types.KeyID
}

type XChaCha20Poly1305KeyData struct {
	TypeURL         string
	Value           []byte
	KeyMaterialType types.KeyMaterialType
	Version         uint32
}

func NewXChaCha20Poly1305Key(id types.KeyID,
	operation types.KeyOperation,
	data *XChaCha20Poly1305KeyData) types.Key {
	return &XChaCha20Poly1305Key{keyID: id, operation: operation, data: data}
}

func (k *XChaCha20Poly1305Key) KeyID() types.KeyID {
	return k.keyID
}

func (k *XChaCha20Poly1305Key) Operation() types.KeyOperation {
	return k.operation
}

func (k *XChaCha20Poly1305Key) Data() types.KeyData {
	return k.data
}

func (data *XChaCha20Poly1305KeyData) GetValue() ([]byte, error) {
	return data.Value, nil
}
func (data *XChaCha20Poly1305KeyData) FromValue([]byte) error {
	return nil
}

func (data *XChaCha20Poly1305KeyData) GetTypeURL() string {
	return data.TypeURL
}
func (data *XChaCha20Poly1305KeyData) GetKeyMaterialType() types.KeyMaterialType {
	return data.KeyMaterialType
}
func (data *XChaCha20Poly1305KeyData) GetVersion() uint32 {
	return data.Version
}
