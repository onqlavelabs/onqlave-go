package factories

import (
	"crypto"
	"fmt"
	"hash"

	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager/operations"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager/primitives"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager/services"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager/types"
)

type rsaSSAPKCS1SHAKeyFactory struct {
	randomService services.CPRNGService
}

func NewRSASSAPKCS1SHAKeyFactory(randomService services.CPRNGService) types.WrappingKeyFactory {
	return &rsaSSAPKCS1SHAKeyFactory{randomService: randomService}
}

func RSAHashFunc(hashAlg string) (func() hash.Hash, crypto.Hash, error) {
	if err := HashSafeForSignature(hashAlg); err != nil {
		return nil, 0, err
	}
	hashFunc := primitives.GetHashFunc(hashAlg)
	if hashFunc == nil {
		return nil, 0, fmt.Errorf("invalid hash function: %q", hashAlg)
	}
	hashID, err := hashID(hashAlg)
	if err != nil {
		return nil, 0, err
	}
	return hashFunc, hashID, nil
}

func hashID(hashAlg string) (crypto.Hash, error) {
	switch hashAlg {
	case "SHA256":
		return crypto.SHA256, nil
	case "SHA384":
		return crypto.SHA384, nil
	case "SHA512":
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("invalid hash function: %q", hashAlg)
	}
}

// HashSafeForSignature checks whether a hash function is safe to use with digital signatures
// that require collision resistance.
func HashSafeForSignature(hashAlg string) error {
	switch hashAlg {
	case "SHA256", "SHA384", "SHA512":
		return nil
	default:
		return fmt.Errorf("hash function not safe for digital signatures: %q", hashAlg)
	}
}

func hashName(h types.HashType) string {
	return types.HashTypeName[int32(h)]
}

func (factory *rsaSSAPKCS1SHAKeyFactory) Primitive(operation types.WrappingKeyOperation) (types.Unwrapping, error) {
	format := operation.GetFormat().(*operations.RsaSsaPkcs1KeyFormat)
	hashFunc, hashID, err := RSAHashFunc(hashName(format.Hash))
	if err != nil {
		return nil, err
	}
	ret, err := primitives.NewRSASSAPKCS1SHA(hashFunc, hashID, factory.randomService)
	if err != nil {
		return nil, fmt.Errorf("rsa_ssa_key_manager: cannot create new primitive: %s", err)
	}
	return ret, nil
}
