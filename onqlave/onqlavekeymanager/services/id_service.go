package services

import (
	"github.com/google/uuid"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager/types"
)

type IDService interface {
	NewStringID() string
	NewKeyID() types.KeyID
}

type idService struct {
	randomService CPRNGService
}

func NewIDGenerationService(randomService CPRNGService) IDService {
	return &idService{randomService: randomService}
}

func (s *idService) NewStringID() string {
	return uuid.NewString()
}

func (s *idService) NewKeyID() types.KeyID {
	ret := types.KeyID(s.randomService.GetRandomUint32())
	return ret
}
