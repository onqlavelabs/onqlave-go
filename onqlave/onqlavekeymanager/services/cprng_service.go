package services

import (
	"crypto/rand"
	"encoding/binary"
	"io"
)

type CPRNGService interface {
	GetRandomBytes(n uint32) []byte
	GetRandomUint32() uint32
	GetRandomReader() io.Reader
}

type cprgnService struct {
}

func NewCPRNGService() CPRNGService {
	return &cprgnService{}
}

// GetRandomBytes randomly generates n bytes.
func (s *cprgnService) GetRandomBytes(size uint32) []byte {
	buf := make([]byte, size)
	_, err := rand.Read(buf)
	if err != nil {
		panic(err) // out of randomness, should never happen
	}
	return buf
}

// GetRandomUint32 randomly generates an unsigned 32-bit integer.
func (s *cprgnService) GetRandomUint32() uint32 {
	b := s.GetRandomBytes(4)
	return binary.BigEndian.Uint32(b)
}

func (s *cprgnService) GetRandomReader() io.Reader {
	return rand.Reader
}
