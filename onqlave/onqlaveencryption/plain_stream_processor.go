package onqlaveencryption

import (
	"encoding/binary"
	"io"

	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager/types"
)

type PlainStreamProcessor interface {
	WriteHeader(algorithm types.AlgorithmSeriliser) error
	WritePacket(packet []byte) error
}

func NewPlainStreamProcessor(cipherStream io.Writer) PlainStreamProcessor {
	return &plainStreamProcessor{cipherStream: cipherStream}
}

type plainStreamProcessor struct {
	cipherStream io.Writer
}

func (processor *plainStreamProcessor) WriteHeader(algorithm types.AlgorithmSeriliser) error {
	header, err := algorithm.Serialise()
	if err != nil {
		return err
	}
	_, err = processor.cipherStream.Write(header)
	return err
}

func (processor *plainStreamProcessor) WritePacket(packet []byte) error {
	dataLen := make([]byte, 4)
	binary.BigEndian.PutUint32(dataLen, uint32(len(packet)))
	_, err := processor.cipherStream.Write(dataLen)
	if err != nil {
		return err
	}
	_, err = processor.cipherStream.Write(packet)
	return err
}
