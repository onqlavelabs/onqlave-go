package onqlaveencryption

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"github.com/onqlavelabs/onqlave-go/onqlave/onqlaveconnection"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavecredentials"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlaveerrors"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager/factories"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager/operations"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager/services"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager/types"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavelogger"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavemessages"
)

// We might be able to break it down to different interfaces
type Encryption struct {
	keyManager    onqlavekeymanager.KeyManager
	onqlavelogger *onqlavelogger.Logger
	operations    map[string]types.KeyOperation
}

func NewEncryption(opts ...Option) *Encryption {
	options := &onqlavekeymanager.Configuration{
		Credential: &onqlavecredentials.Credential{},
		Retry:      onqlaveconnection.DefaultRetrySettings,
		ArxURL:     INVALID_ARX,
	}
	for _, o := range opts {
		o.apply(options)
	}
	onqlavelogger := onqlavelogger.NewLog(onqlavemessages.SDK, onqlavelogger.WithDevelopment(options.Debug))
	randomService := services.NewCPRNGService()
	idService := services.NewIDGenerationService(randomService)
	keyManager := onqlavekeymanager.NewKeyManager(options, randomService)
	aeadGcmKeyFactory := factories.NewAEADGCMKeyFactory(idService, randomService)
	xchchaKeyFactory := factories.NewXChaCha20Poly1305KeyFactory(idService, randomService)

	operations := map[string]types.KeyOperation{
		types.Aesgcm128:         operations.NewAES128GCMKeyOperation(aeadGcmKeyFactory),
		types.Aesgcm256:         operations.NewAES256GCMKeyOperation(aeadGcmKeyFactory),
		types.XChacha20poly1305: operations.NewXChaCha20Poly1305KeyOperation(xchchaKeyFactory),
	}
	return &Encryption{keyManager: keyManager, onqlavelogger: onqlavelogger, operations: operations}
}

func (service *Encryption) Close() {
	service.keyManager = nil
	//service = nil
}

func (service *Encryption) initEncryptOperation(operation string) (types.AlgorithmSeriliser, types.AEAD, *onqlaveerrors.OnqlaveError) {
	edk, dk, algo, err := service.keyManager.FetchEncryptionKey()
	if err != nil {
		return nil, nil, err
	}
	ops, ok := service.operations[algo]
	if !ok {
		return nil, nil, onqlaveerrors.NewOnqlaveErrorWrapf(onqlaveerrors.Server, nil, onqlavemessages.KEY_INVALID_ENCRYPTION_OPERATION, operation)
	}
	factory := ops.GetFactory()
	key, errP := factory.NewKeyFromData(ops, dk)
	if errP != nil {
		return nil, nil, onqlaveerrors.NewOnqlaveErrorWrapf(onqlaveerrors.Server, errP, onqlavemessages.ENCRYPTION_OPERATION_FAILED, operation)
	}
	primitive, errP := factory.Primitive(key)
	if errP != nil {
		return nil, nil, onqlaveerrors.NewOnqlaveErrorWrapf(onqlaveerrors.Server, errP, onqlavemessages.ENCRYPTION_OPERATION_FAILED, operation)
	}
	algorithm := types.NewAlgorithmSerialiser(0, algo, edk)
	return algorithm, primitive, nil
}

func (service *Encryption) initDecryptOperation(operation string, algo types.AlogorithmDeserialiser) (types.AEAD, *onqlaveerrors.OnqlaveError) {
	dk, err := service.keyManager.FetchDecryptionKey(algo.Key())
	if err != nil {
		return nil, err
	}
	//now we have the keys from service. We can use them to decrypt the cipher data
	ops, ok := service.operations[algo.Algorithm()]
	if !ok {
		return nil, onqlaveerrors.NewOnqlaveErrorWrapf(onqlaveerrors.Server, nil, onqlavemessages.KEY_INVALID_DECRYPTION_OPERATION, operation)
	}
	factory := ops.GetFactory()
	key, errP := factory.NewKeyFromData(ops, dk)
	if errP != nil {
		return nil, onqlaveerrors.NewOnqlaveErrorWrapf(onqlaveerrors.Server, errP, onqlavemessages.ENCRYPTION_OPERATION_FAILED, operation)
	}
	primitive, errP := factory.Primitive(key)
	if errP != nil {
		return nil, onqlaveerrors.NewOnqlaveErrorWrapf(onqlaveerrors.Server, errP, onqlavemessages.ENCRYPTION_OPERATION_FAILED, operation)
	}
	return primitive, nil
}

func (service *Encryption) Encrypt(plainData, associatedData []byte) ([]byte, *onqlaveerrors.OnqlaveError) {
	operation := "Encrypt"
	start := time.Now().UTC()
	service.onqlavelogger.Debug(fmt.Sprintf(onqlavemessages.ENCRYPTING_OPERATION, operation))

	header, primitive, err := service.initEncryptOperation(operation)
	if err != nil {
		return nil, err
	}
	cipherData, errP := primitive.Encrypt(plainData, associatedData)
	if errP != nil {
		return nil, onqlaveerrors.NewOnqlaveErrorWrapf(onqlaveerrors.Server, errP, onqlavemessages.ENCRYPTION_OPERATION_FAILED, operation)
	}
	cipherStream := new(bytes.Buffer)
	processor := NewPlainStreamProcessor(cipherStream)
	errP = processor.WriteHeader(header)
	if errP != nil {
		return nil, onqlaveerrors.NewOnqlaveErrorWrapf(onqlaveerrors.Server, errP, onqlavemessages.ENCRYPTION_OPERATION_FAILED, operation)
	}
	errP = processor.WritePacket(cipherData)
	if errP != nil {
		return nil, onqlaveerrors.NewOnqlaveErrorWrapf(onqlaveerrors.Server, errP, onqlavemessages.ENCRYPTION_OPERATION_FAILED, operation)
	}
	service.onqlavelogger.Debug(fmt.Sprintf(onqlavemessages.ENCRYPTED_OPERATION, operation, time.Since(start)))
	return cipherStream.Bytes(), nil
}

func (service *Encryption) Decrypt(cipherData, associatedData []byte) ([]byte, *onqlaveerrors.OnqlaveError) {
	operation := "Decrypt"
	start := time.Now().UTC()
	service.onqlavelogger.Debug(fmt.Sprintf(onqlavemessages.DECRYPTING_OPERATION, operation))

	cipherStream := bytes.NewBuffer(cipherData)
	processor := NewEncryptedStreamProcessor(cipherStream)
	algo, er := processor.ReadHeader()
	if er != nil {
		return nil, onqlaveerrors.NewOnqlaveErrorWrapf(onqlaveerrors.Server, er, onqlavemessages.DECRYPTION_OPERATION_FAILED, operation)
	}

	primitive, err := service.initDecryptOperation(operation, algo)
	if err != nil {
		return nil, err
	}
	cipher, errP := processor.ReadPacket()
	if errP != nil {
		return nil, onqlaveerrors.NewOnqlaveErrorWrapf(onqlaveerrors.Server, errP, onqlavemessages.DECRYPTION_OPERATION_FAILED, operation)
	}
	plainData, errP := primitive.Decrypt(cipher, associatedData)
	if errP != nil {
		return nil, onqlaveerrors.NewOnqlaveErrorWrapf(onqlaveerrors.Server, errP, onqlavemessages.DECRYPTION_OPERATION_FAILED, operation)
	}
	service.onqlavelogger.Debug(fmt.Sprintf(onqlavemessages.DECRYPTED_OPERATION, operation, time.Since(start)))
	return plainData, err
}

func (service *Encryption) EncryptStream(plainStream io.Reader, cipherStream io.Writer, associatedData []byte) *onqlaveerrors.OnqlaveError {
	operation := "EncryptStream"
	start := time.Now().UTC()
	service.onqlavelogger.Debug(fmt.Sprintf(onqlavemessages.ENCRYPTING_OPERATION, operation))

	header, primitive, err := service.initEncryptOperation(operation)
	if err != nil {
		return err
	}
	processor := NewPlainStreamProcessor(cipherStream)
	errP := processor.WriteHeader(header)
	if errP != nil {
		return onqlaveerrors.NewOnqlaveErrorWrapf(onqlaveerrors.Server, errP, onqlavemessages.ENCRYPTION_OPERATION_FAILED, operation)
	}
	var tempBuffer []byte = make([]byte, 32*1024)
	for {
		dataLen, e := plainStream.Read(tempBuffer)
		if e == io.EOF {
			break
		}
		if e != nil {
			return onqlaveerrors.NewOnqlaveErrorWrapf(onqlaveerrors.Server, e, onqlavemessages.ENCRYPTION_OPERATION_FAILED, operation)
		}
		cipherText, errP := primitive.Encrypt(tempBuffer[:dataLen], associatedData)
		if errP != nil {
			return onqlaveerrors.NewOnqlaveErrorWrapf(onqlaveerrors.Server, errP, onqlavemessages.ENCRYPTION_OPERATION_FAILED, operation)
		}
		errP = processor.WritePacket(cipherText)
		if errP != nil {
			return onqlaveerrors.NewOnqlaveErrorWrapf(onqlaveerrors.Server, errP, onqlavemessages.ENCRYPTION_OPERATION_FAILED, operation)
		}
	}
	service.onqlavelogger.Debug(fmt.Sprintf(onqlavemessages.ENCRYPTED_OPERATION, operation, time.Since(start)))
	return nil
}

func (service *Encryption) DecryptStream(cipherStream io.Reader, plainStream io.Writer, associatedData []byte) *onqlaveerrors.OnqlaveError {
	operation := "DecryptStream"
	start := time.Now().UTC()
	service.onqlavelogger.Debug(fmt.Sprintf(onqlavemessages.DECRYPTING_OPERATION, operation))

	processor := NewEncryptedStreamProcessor(cipherStream)
	algo, er := processor.ReadHeader()
	if er != nil {
		return onqlaveerrors.NewOnqlaveErrorWrapf(onqlaveerrors.Server, er, onqlavemessages.DECRYPTION_OPERATION_FAILED, operation)
	}

	primitive, err := service.initDecryptOperation(operation, algo)
	if err != nil {
		return err
	}
	for {
		cipher, errP := processor.ReadPacket()
		if errP == io.EOF {
			break
		}
		if errP != nil {
			return onqlaveerrors.NewOnqlaveErrorWrapf(onqlaveerrors.Server, errP, onqlavemessages.DECRYPTION_OPERATION_FAILED, operation)
		}
		plainData, errP := primitive.Decrypt(cipher, associatedData)
		if errP != nil {
			return onqlaveerrors.NewOnqlaveErrorWrapf(onqlaveerrors.Server, errP, onqlavemessages.DECRYPTION_OPERATION_FAILED, operation)
		}
		_, errP = plainStream.Write(plainData)
		if errP != nil {
			return onqlaveerrors.NewOnqlaveErrorWrapf(onqlaveerrors.Server, errP, onqlavemessages.DECRYPTION_OPERATION_FAILED, operation)
		}
	}
	service.onqlavelogger.Debug(fmt.Sprintf(onqlavemessages.DECRYPTED_OPERATION, operation, time.Since(start)))
	return nil
}

func (service *Encryption) EncryptStructure(plainStructure map[string]interface{}, associatedData []byte) (*types.OnqlaveStructure, *onqlaveerrors.OnqlaveError) {
	operation := "EncryptStructure"
	start := time.Now().UTC()
	service.onqlavelogger.Debug(fmt.Sprintf(onqlavemessages.ENCRYPTING_OPERATION, operation))

	algo, primitive, err := service.initEncryptOperation(operation)
	if err != nil {
		return nil, err
	}
	header, errP := algo.Serialise()
	if errP != nil {
		return nil, onqlaveerrors.NewOnqlaveErrorWrapf(onqlaveerrors.Server, errP, onqlavemessages.ENCRYPTION_OPERATION_FAILED, operation)
	}
	resolver := types.NewTypeResolver()
	result := map[string][]byte{}
	for key, value := range plainStructure {
		plainData, errP := resolver.Serialise(key, value)
		if errP != nil {
			return nil, onqlaveerrors.NewOnqlaveErrorWrapf(onqlaveerrors.Server, errP, onqlavemessages.ENCRYPTION_OPERATION_FAILED, operation)
		}
		cipherData, errP := primitive.Encrypt(plainData, associatedData)
		if errP != nil {
			return nil, onqlaveerrors.NewOnqlaveErrorWrapf(onqlaveerrors.Server, errP, onqlavemessages.ENCRYPTION_OPERATION_FAILED, operation)
		}
		result[key] = cipherData
	}
	service.onqlavelogger.Debug(fmt.Sprintf(onqlavemessages.ENCRYPTED_OPERATION, operation, time.Since(start)))
	return &types.OnqlaveStructure{
		Edk:     header,
		Embeded: result,
	}, nil
}

func (service *Encryption) DecryptStructure(cipherStructure *types.OnqlaveStructure, associatedData []byte) (map[string]interface{}, *onqlaveerrors.OnqlaveError) {
	operation := "DecryptStructure"
	start := time.Now().UTC()
	service.onqlavelogger.Debug(fmt.Sprintf(onqlavemessages.DECRYPTING_OPERATION, operation))

	cipherStream := bytes.NewBuffer(cipherStructure.Edk)
	processor := NewEncryptedStreamProcessor(cipherStream)
	algo, er := processor.ReadHeader()
	if er != nil {
		return nil, onqlaveerrors.NewOnqlaveErrorWrapf(onqlaveerrors.Server, er, onqlavemessages.DECRYPTION_OPERATION_FAILED, operation)
	}
	primitive, err := service.initDecryptOperation(operation, algo)
	if err != nil {
		return nil, err
	}
	resolver := types.NewTypeResolver()
	result := map[string]interface{}{}
	for key, value := range cipherStructure.Embeded {
		plainData, errP := primitive.Decrypt(value, associatedData)
		if errP != nil {
			return nil, onqlaveerrors.NewOnqlaveErrorWrapf(onqlaveerrors.Server, errP, onqlavemessages.DECRYPTION_OPERATION_FAILED, operation)
		}
		plainValue, errP := resolver.Deserialise(key, plainData)
		if errP != nil {
			return nil, onqlaveerrors.NewOnqlaveErrorWrapf(onqlaveerrors.Server, errP, onqlavemessages.DECRYPTION_OPERATION_FAILED, operation)
		}
		result[key] = plainValue
	}
	service.onqlavelogger.Debug(fmt.Sprintf(onqlavemessages.DECRYPTED_OPERATION, operation, time.Since(start)))
	return result, err
}
