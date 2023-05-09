package onqlavekeymanager

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/onqlavelabs/onqlave-go/onqlave/onqlaveconnection"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavecontracts/requests"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavecontracts/responses"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavecredentials"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlaveerrors"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager/factories"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager/operations"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager/services"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager/types"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavelogger"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavemessages"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlaveutils"
)

type Configuration struct {
	Credential *onqlavecredentials.Credential
	Retry      *onqlaveconnection.RetrySettings
	ArxURL     string
	Debug      bool
}

type KeyManager interface {
	FetchEncryptionKey() (edk []byte, dk []byte, algorithm string, err *onqlaveerrors.OnqlaveError)
	FetchDecryptionKey(edk []byte) (dk []byte, err *onqlaveerrors.OnqlaveError)
}

type keyManager struct {
	keyManager    onqlaveconnection.Connection
	configuration *Configuration
	onqlavelogger *onqlavelogger.Logger
	operations    map[string]types.WrappingKeyOperation
}

const (
	ENCRYPT_RESOURCE_URL string = "oe2/keymanager/encrypt"
	DECRYPT_RESOURCE_URL string = "oe2/keymanager/decrypt"
)

func NewKeyManager(configuration *Configuration, randomService services.CPRNGService) KeyManager {
	hasher := onqlaveutils.NewHasher()
	onqlavelogger := onqlavelogger.NewLog(onqlavemessages.SDK)
	//TODO: we need to add extra logic here.
	index := strings.LastIndex(configuration.ArxURL, "/")
	config := onqlaveconnection.Configuration{
		ArxURL: configuration.ArxURL[:index],
		ArxID:  configuration.ArxURL[index+1:],
		Credential: &onqlaveconnection.Credential{
			AccessKey:  configuration.Credential.AccessKey,
			SigningKey: configuration.Credential.SigningKey,
		},
		Retry: configuration.Retry,
	}
	httpClient := onqlaveconnection.NewConnection(&config, hasher, onqlavelogger)
	rsaSSAPKCS1KeyFactory := factories.NewRSASSAPKCS1SHAKeyFactory(randomService)
	operations := map[string]types.WrappingKeyOperation{
		types.RsaSsapkcs12048sha256f4: operations.NewRSASSAPKCS1SHA2562048KeyOperation(rsaSSAPKCS1KeyFactory),
	}

	return &keyManager{keyManager: httpClient, configuration: configuration, onqlavelogger: onqlavelogger, operations: operations}
}

func (c *keyManager) FetchEncryptionKey() (edk []byte, dk []byte, algorithm string, err *onqlaveerrors.OnqlaveError) {
	operation := "FetchEncryptionKey"
	start := time.Now().UTC()
	request := requests.EncryptionOpenRequest{}
	c.onqlavelogger.Debug(fmt.Sprintf(onqlavemessages.FETCHING_ENCRYPTION_KEY_OPERATION, operation))
	data, err := c.keyManager.Post(ENCRYPT_RESOURCE_URL, &request)
	if err != nil {
		return nil, nil, "", err
	}
	var response responses.EncryptionOpenResponse
	error := json.Unmarshal(data, &response)
	if error != nil {
		return nil, nil, "", onqlaveerrors.NewOnqlaveErrorWrapf(onqlaveerrors.Server, error, onqlavemessages.FETCHING_ENCRYPTION_KEY_RESPONSE_UNMARSHALING_FAILED, operation)
	}
	edk, _ = base64.StdEncoding.DecodeString(response.DK.EDK)
	wdk, _ := base64.StdEncoding.DecodeString(response.DK.WDK)
	epk, _ := base64.StdEncoding.DecodeString(response.WK.EPK)
	fp, _ := base64.StdEncoding.DecodeString(response.WK.KeyFingerprint)
	wrappingAlgorithm := response.SecurityModel.WrappingAlgorithm
	algorithm = response.SecurityModel.Algorithm
	dk, err = c.unwrapKey(wrappingAlgorithm, operation, wdk, epk, fp, []byte(c.configuration.Credential.SecretKey))
	c.onqlavelogger.Debug(fmt.Sprintf(onqlavemessages.FETCHED_ENCRYPTION_KEY_OPERATION, operation, time.Since(start)))
	return edk, dk, algorithm, err
}

func (c *keyManager) FetchDecryptionKey(edk []byte) (dk []byte, err *onqlaveerrors.OnqlaveError) {
	operation := "FetchDecryptionKey"
	start := time.Now().UTC()
	request := requests.DecryptionOpenRequest{
		EDK: base64.StdEncoding.EncodeToString(edk),
	}
	c.onqlavelogger.Debug(fmt.Sprintf(onqlavemessages.FETCHING_DECRYPTION_OPERATION, operation))
	data, err := c.keyManager.Post(DECRYPT_RESOURCE_URL, &request)
	if err != nil {
		return nil, err
	}
	var response responses.DecryptionOpenResponse
	error := json.Unmarshal(data, &response)
	if error != nil {
		return nil, onqlaveerrors.NewOnqlaveErrorWrapf(onqlaveerrors.Server, error, onqlavemessages.FETCHING_DECRYPTION_KEY_RESPONSE_UNMARSHALING_FAILED, operation)
	}
	wdk, _ := base64.StdEncoding.DecodeString(response.DK.WDK)
	epk, _ := base64.StdEncoding.DecodeString(response.WK.EPK)
	fp, _ := base64.StdEncoding.DecodeString(response.WK.KeyFingerprint)
	wrappingAlgorithm := response.SecurityModel.WrappingAlgorithm
	dk, err = c.unwrapKey(wrappingAlgorithm, operation, wdk, epk, fp, []byte(c.configuration.Credential.SecretKey))
	c.onqlavelogger.Debug(fmt.Sprintf(onqlavemessages.FETCHED_DECRYPTION_OPERATION, operation, time.Since(start)))
	return dk, err
}

func (c *keyManager) unwrapKey(wrappingAlgorithm string, operation string, wdk []byte, epk []byte, fp []byte, password []byte) (dk []byte, err *onqlaveerrors.OnqlaveError) {
	wrappingOperation := c.operations[wrappingAlgorithm]
	if wrappingOperation == nil {
		return nil, onqlaveerrors.NewOnqlaveErrorWrapf(onqlaveerrors.Server, nil, onqlavemessages.KEY_INVALID_WRAPPING_ALGO, operation)
	}
	factory := wrappingOperation.GetFactory()
	primitive, errP := factory.Primitive(wrappingOperation)
	if errP != nil {
		return nil, onqlaveerrors.NewOnqlaveErrorWrapf(onqlaveerrors.Server, errP, onqlavemessages.KEY_INVALID_WRAPPING_OPERATION, operation)
	}
	dk, errW := primitive.UnwrapKey(wdk, epk, fp, password)
	if errW != nil {
		return nil, onqlaveerrors.NewOnqlaveErrorWrapf(onqlaveerrors.Server, errW, onqlavemessages.KEY_UNWRAPPING_KEY_FAILED, operation)
	}
	return dk, nil
}
