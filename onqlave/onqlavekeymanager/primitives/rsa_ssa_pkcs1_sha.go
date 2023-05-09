package primitives

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/pem"
	"errors"
	"hash"

	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager/services"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager/types"
	"github.com/youmark/pkcs8"
)

// RSASSAPKCS1SHA is an implementation of AEAD interface.
type RSASSAPKCS1SHA struct {
	randomService services.CPRNGService
	hashFunc      func() hash.Hash
	hashID        crypto.Hash
}

// Assert that RSASSAPKCS1SHA implements the Wrapping interface.
var _ types.Unwrapping = (*RSASSAPKCS1SHA)(nil)

// GetHashFunc returns the corresponding hash function of the given hash name.
func GetHashFunc(hash string) func() hash.Hash {
	switch hash {
	case "SHA1":
		return sha1.New
	case "SHA224":
		return sha256.New224
	case "SHA256":
		return sha256.New
	case "SHA384":
		return sha512.New384
	case "SHA512":
		return sha512.New
	default:
		return nil
	}
}

// NewRSASSAPKCS1SHA returns an RSASSAPKCS1SHA instance
func NewRSASSAPKCS1SHA(hashFunc func() hash.Hash, hashID crypto.Hash, randomService services.CPRNGService) (types.Unwrapping, error) {
	return &RSASSAPKCS1SHA{hashFunc: hashFunc, hashID: hashID, randomService: randomService}, nil
}

// Unwrap the wrapped private key.
func (a *RSASSAPKCS1SHA) UnwrapKey(wdk []byte, epk []byte, fp []byte, password []byte) (dk []byte, err error) {
	var privateKey *rsa.PrivateKey
	block, rem := pem.Decode(epk)
	if len(rem) == 0 {
		privateKey, err = pkcs8.ParsePKCS8PrivateKeyRSA(block.Bytes, password)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("invalid wrapping key format")
	}
	if err == nil {
		dk, err = rsa.DecryptOAEP(a.hashFunc(), a.randomService.GetRandomReader(), privateKey, wdk, nil)
		if err != nil {
			return nil, errors.New("invalid key")
		}
	}
	// derCert := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
	// hash := sha256.New()
	// _, err = hash.Write(derCert)
	// if err != nil {
	// 	return nil, err
	// }
	// if strings.Compare(string(hash.Sum(nil)), string(fp)) != 0 {
	// 	return nil, errors.New("invalid wrapping key")
	// }
	return dk, nil
}
