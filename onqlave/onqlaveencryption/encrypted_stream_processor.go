package onqlaveencryption

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager/types"
)

type EncryptedStreamProcessor interface {
	ReadHeader() (types.AlogorithmDeserialiser, error)
	ReadPacket() ([]byte, error)
}

func NewEncryptedStreamProcessor(cipherStream io.Reader) EncryptedStreamProcessor {
	return &encryptedStreamProcessor{cipherStream: cipherStream}
}

type encryptedStreamProcessor struct {
	cipherStream io.Reader
}

func (processor *encryptedStreamProcessor) ReadHeader() (types.AlogorithmDeserialiser, error) {
	headerLenBuffer := make([]byte, 4)
	dataLen, err := processor.cipherStream.Read(headerLenBuffer)
	if err != nil {
		return nil, err
	}
	if dataLen < 4 {
		return nil, fmt.Errorf("invalid cipher data")
	}
	headerLen := binary.BigEndian.Uint32(headerLenBuffer)
	headerBuffer := make([]byte, headerLen-4)
	dataLen, err = processor.cipherStream.Read(headerBuffer)
	if err != nil {
		return nil, err
	}
	if dataLen < int(headerLen)-4 {
		return nil, fmt.Errorf("invalid cipher data")
	}
	algorithm := types.NewAlgorithmDeserialiser()
	_, err = algorithm.Deserialise(append(headerLenBuffer, headerBuffer...))
	if err != nil {
		return nil, err
	}
	return algorithm, nil
}

func (processor *encryptedStreamProcessor) ReadPacket() ([]byte, error) {
	packetLenBuffer := make([]byte, 4)
	dataLen, err := processor.cipherStream.Read(packetLenBuffer)
	if err != nil {
		return nil, err
	}
	if dataLen < 4 {
		return nil, fmt.Errorf("invalid cipher data")
	}
	packetLen := binary.BigEndian.Uint32(packetLenBuffer)
	buffer := make([]byte, packetLen)
	dataLen, err = processor.cipherStream.Read(buffer)
	if dataLen < int(packetLen) {
		return nil, fmt.Errorf("invalid cipher data")
	}
	return buffer, err
}
