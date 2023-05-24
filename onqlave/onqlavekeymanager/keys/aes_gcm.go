package keys

import (
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager/types"
)

type AesGcmKey struct {
	operation types.KeyOperation
	data      *AesGcmKeyData
	keyID     types.KeyID
}

type AesGcmKeyData struct {
	TypeURL         string
	Value           []byte
	KeyMaterialType types.KeyMaterialType
	Version         uint32
}

func NewAesGcmKey(id types.KeyID, operation types.KeyOperation, data *AesGcmKeyData) types.Key {
	return &AesGcmKey{keyID: id, operation: operation, data: data}
}

func (k *AesGcmKey) KeyID() types.KeyID {
	return k.keyID
}

func (k *AesGcmKey) Operation() types.KeyOperation {
	return k.operation
}

func (k *AesGcmKey) Data() types.KeyData {
	return k.data
}

func (data *AesGcmKeyData) FromValue([]byte) error {
	return nil
}

func (data *AesGcmKeyData) GetValue() ([]byte, error) {
	return data.Value, nil
}
func (data *AesGcmKeyData) GetTypeURL() string {
	return data.TypeURL
}
func (data *AesGcmKeyData) GetKeyMaterialType() types.KeyMaterialType {
	return data.KeyMaterialType
}
func (data *AesGcmKeyData) GetVersion() uint32 {
	return data.Version
}
