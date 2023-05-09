package types

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"reflect"
	"time"
)

type TypeResolver interface {
	Serialise(name string, input interface{}) ([]byte, error)
	Deserialise(name string, input []byte) (interface{}, error)
}

type typeResolver struct {
}

func NewTypeResolver() TypeResolver {
	return &typeResolver{}
}

func (resolver *typeResolver) Serialise(name string, input interface{}) ([]byte, error) {
	buffer := bytes.NewBuffer(nil)
	val := reflect.ValueOf(input)
	kind := val.Kind()
	buffer.WriteByte(byte(kind))
	i := input
	switch input.(type) {
	case bool:
		b := i.(bool)
		if b {
			buffer.WriteByte(1)
		} else {
			buffer.WriteByte(0)
		}
	case int8:
		v := i.(int8)
		buffer.WriteByte(byte(v))
	case int16:
		data := make([]byte, 2)
		v := i.(int16)
		binary.BigEndian.PutUint16(data, uint16(v))
		buffer.Write(data)
	case int32:
		data := make([]byte, 4)
		v := i.(int32)
		binary.BigEndian.PutUint32(data, uint32(v))
		buffer.Write(data)
	case int64:
		data := make([]byte, 8)
		v := i.(int64)
		binary.BigEndian.PutUint64(data, uint64(v))
		buffer.Write(data)
	case uint8:
		v := i.(int8)
		buffer.WriteByte(byte(v))
	case uint16:
		data := make([]byte, 2)
		v := i.(uint16)
		binary.BigEndian.PutUint16(data, uint16(v))
		buffer.Write(data)
	case uint32:
		data := make([]byte, 4)
		v := i.(uint32)
		binary.BigEndian.PutUint32(data, uint32(v))
		buffer.Write(data)
	case uint64:
		data := make([]byte, 8)
		v := i.(uint64)
		binary.BigEndian.PutUint64(data, uint64(v))
		buffer.Write(data)
	case float32:
		data := make([]byte, 4)
		v := i.(float32)
		binary.BigEndian.PutUint32(data, uint32(math.Float32bits(v)))
		buffer.Write(data)
	case float64:
		data := make([]byte, 8)
		v := i.(float64)
		binary.BigEndian.PutUint64(data, uint64(math.Float64bits(v)))
		buffer.Write(data)
	case time.Time:
		data := make([]byte, 8)
		v := i.(time.Time)
		binary.BigEndian.PutUint64(data, uint64(v.Unix()))
		buffer.Write(data)
	case string:
		v := i.(string)
		buffer.Write([]byte(v))
	case []byte:
		v := i.([]byte)
		buffer.Write(v)
	default:
		return nil, fmt.Errorf("%s: unsupported type: %s", name, kind)
	}
	return buffer.Bytes(), nil
}

func (resolver *typeResolver) Deserialise(name string, input []byte) (interface{}, error) {
	kind := reflect.Kind(input[0])
	var val interface{}
	switch kind {
	case reflect.Bool:
		v := input[1]
		if v == 1 {
			val = true
		} else {
			val = false
		}
	case reflect.Int8:
		v := input[1]
		val = int8(v)
	case reflect.Int16:
		v := binary.BigEndian.Uint16(input[1:])
		val = int16(v)
	case reflect.Int32:
		v := binary.BigEndian.Uint32(input[1:])
		val = int32(v)
	case reflect.Int64:
		v := binary.BigEndian.Uint64(input[1:])
		val = int64(v)
	case reflect.Uint8:
		v := input[1]
		val = uint8(v)
	case reflect.Uint16:
		v := binary.BigEndian.Uint16(input[1:])
		val = uint16(v)
	case reflect.Uint32:
		v := binary.BigEndian.Uint32(input[1:])
		val = uint32(v)
	case reflect.Uint64:
		v := binary.BigEndian.Uint64(input[1:])
		val = uint64(v)
	case reflect.Float32:
		v := binary.BigEndian.Uint32(input[1:])
		val = math.Float32frombits(v)
	case reflect.Float64:
		v := binary.BigEndian.Uint64(input[1:])
		val = math.Float64frombits(v)
	case reflect.String:
		v := input[1:]
		val = string(v)
	case reflect.Struct:
		v := binary.BigEndian.Uint64(input[1:])
		val = time.Unix(int64(v), 0)
	case reflect.Slice:
		v := input[1:]
		val = v
	default:
		return nil, fmt.Errorf("%s: unsupported type: %s", name, kind)
	}
	return val, nil
}

type OnqlaveStructure struct {
	Embeded map[string][]byte
	Edk     []byte
}

type WrappingKeyFactory interface {
	Primitive(operation WrappingKeyOperation) (Unwrapping, error)
}

type KeyFactory interface {
	NewKey(operation KeyOperation) (Key, error)
	NewKeyFromData(operation KeyOperation, keyData []byte) (Key, error)
	Primitive(key Key) (AEAD, error)
}

const (
	Aesgcm128               = "aes-gcm-128"
	Aesgcm256               = "aes-gcm-256"
	XChacha20poly1305       = "xcha-cha-20-poly-1305"
	RsaSsapkcs12048sha256f4 = "RSA_SSA_PKCS1_2048_SHA256_F4"
)

// Enum value maps for KeyStatusType.
var (
	AlgorithmTypeName = map[int32]string{
		0: "unknown_algorithm",
		1: "aes-gcm-128",
		2: "aes-gcm-256",
		3: "xcha-cha-20-poly-1305",
	}
	AlgorithmTypeValue = map[string]int32{
		"unknown_algorithm":     0,
		"aes-gcm-128":           1,
		"aes-gcm-256":           2,
		"xcha-cha-20-poly-1305": 3,
	}
)

type WrappingKeyOperation interface {
	GetFormat() KeyFormat
	GetFactory() WrappingKeyFactory
}

type KeyOperation interface {
	GetFormat() KeyFormat
	GetFactory() KeyFactory
}

type KeyFormat interface {
	Size() uint32
}

/*
AEAD is the interface for authenticated encryption with associated data.
Implementations of this interface are secure against adaptive chosen ciphertext attacks.
Encryption with associated data ensures authenticity and integrity of that data, but not
its secrecy. (see RFC 5116, https://tools.ietf.org/html/rfc5116)
*/
type AEAD interface {
	// Encrypt encrypts plaintext with associatedData as associated data.
	// The resulting ciphertext allows for checking authenticity and integrity of associated data
	// associatedData, but does not guarantee its secrecy.
	Encrypt(plaintext, associatedData []byte) ([]byte, error)

	// Decrypt decrypts ciphertext with associatedData as associated data.
	// The decryption verifies the authenticity and integrity of the associated data, but there are
	// no guarantees with respect to secrecy of that data.
	Decrypt(ciphertext, associatedData []byte) ([]byte, error)
}

type Unwrapping interface {
	UnwrapKey(wdk []byte, epk []byte, fp []byte, password []byte) (dk []byte, err error)
}

type KeyID uint32

type algorithm struct {
	version byte
	algo    byte
	key     []byte
}

type AlgorithmSeriliser interface {
	Serialise() ([]byte, error)
}

type AlogorithmDeserialiser interface {
	Deserialise(buffer []byte) (int, error)
	Key() []byte
	Version() byte
	Algorithm() string
}

func NewAlgorithmSerialiser(version byte, algo string, key []byte) AlgorithmSeriliser {
	return &algorithm{key: key, algo: byte(AlgorithmTypeValue[algo]), version: version}
}

func NewAlgorithmDeserialiser() AlogorithmDeserialiser {
	return &algorithm{}
}

func (algo *algorithm) Key() []byte {
	return algo.key
}

func (algo *algorithm) Algorithm() string {
	return AlgorithmTypeName[int32(algo.algo)]
}

func (algo *algorithm) Version() byte {
	return algo.version
}

func (algo *algorithm) Serialise() ([]byte, error) {
	buf := new(bytes.Buffer)
	headerLen := make([]byte, 4)
	binary.BigEndian.PutUint32(headerLen, uint32(7+len(algo.key)))
	buf.Write(headerLen)
	buf.WriteByte(algo.version)
	buf.WriteByte(algo.algo)
	buf.WriteByte(byte(len(algo.key)))
	buf.Write(algo.key)
	return buf.Bytes(), nil
}

func (algo *algorithm) Deserialise(buffer []byte) (int, error) {
	if len(buffer) < 7 {
		return 0, fmt.Errorf("invalid cipher data")
	}
	headerLen := binary.BigEndian.Uint32(buffer[:4])
	if len(buffer) < int(headerLen) {
		return 0, fmt.Errorf("invalid cipher data")
	}
	algo.version = buffer[4]
	algo.algo = buffer[5]
	keyLen := buffer[6]

	algo.key = buffer[7 : 7+keyLen]
	return int(headerLen), nil
}

type KeyData interface {
	GetValue() ([]byte, error)
	FromValue(data []byte) error
	GetTypeURL() string
	GetKeyMaterialType() KeyMaterialType
	GetVersion() uint32
}

type Key interface {
	KeyID() KeyID
	Operation() KeyOperation
	Data() KeyData
}

type HashType int32

const (
	HashTypeUNKNOWNHASH HashType = 0
	HashTypeSHA1        HashType = 1
	HashTypeSHA384      HashType = 2
	HashTypeSHA256      HashType = 3
	HashTypeSHA512      HashType = 4
	HashTypeSHA224      HashType = 5
)

// Enum value maps for HashType.
var (
	HashTypeName = map[int32]string{
		0: "UNKNOWN_HASH",
		1: "SHA1",
		2: "SHA384",
		3: "SHA256",
		4: "SHA512",
		5: "SHA224",
	}
	HashTypeValue = map[string]int32{
		"UNKNOWN_HASH": 0,
		"SHA1":         1,
		"SHA384":       2,
		"SHA256":       3,
		"SHA512":       4,
		"SHA224":       5,
	}
)

type KeyMaterialType int32

const (
	KeyMaterialUNKNOWNKEYMATERIAL KeyMaterialType = 0
	KeyMaterialSYMMETRIC          KeyMaterialType = 1
	KeyMaterialASYMMETRICPRIVATE  KeyMaterialType = 2
	KeyMaterialASYMMETRICPUBLIC   KeyMaterialType = 3
	KeyMaterialREMOTE             KeyMaterialType = 4 // points to a remote key, i.e., in a KMS.
)

// Enum value maps for KeyData_KeyMaterialType.
var (
	KeyMaterialTypeName = map[int32]string{
		0: "UNKNOWN_KEYMATERIAL",
		1: "SYMMETRIC",
		2: "ASYMMETRIC_PRIVATE",
		3: "ASYMMETRIC_PUBLIC",
		4: "REMOTE",
	}
	KeyMaterialTypeValue = map[string]int32{
		"UNKNOWN_KEYMATERIAL": 0,
		"SYMMETRIC":           1,
		"ASYMMETRIC_PRIVATE":  2,
		"ASYMMETRIC_PUBLIC":   3,
		"REMOTE":              4,
	}
)
