package onqlaveutils

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"

	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavecontracts/requests"
)

type Hasher interface {
	Digest(body requests.OnqlaveRequest) (digest string, err error)
	Sign(headers map[string]string, signingKey string) (signature string, err error)
}

type hasher struct {
}

func NewHasher() Hasher {
	return &hasher{}
}

func (h *hasher) Digest(body requests.OnqlaveRequest) (digest string, err error) {
	digestHash := sha512.New()
	content, err := body.GetContent()
	if err != nil {
		return "", err
	}
	_, err = digestHash.Write(content)
	if err != nil {
		return "", err
	}
	sum := digestHash.Sum(nil)
	digest = fmt.Sprintf("SHA512=%s", base64.StdEncoding.EncodeToString(sum))
	return digest, nil
}

func (h *hasher) Sign(headers map[string]string, signingKey string) (signature string, err error) {
	signatureHash := hmac.New(sha512.New, []byte(signingKey))

	var keys []string
	for hdrName, hdrValue := range headers {
		if hdrValue != "" {
			keys = append(keys, string(hdrName))
		}
	}
	sort.Strings(keys)

	for _, hdrName := range keys {
		input := fmt.Sprintf("%s:%s", strings.ToLower(string(hdrName)), headers[hdrName])
		signatureHash.Write([]byte(input))
	}
	sum := signatureHash.Sum(nil)
	signature = fmt.Sprintf("HMAC-SHA512=%s", base64.StdEncoding.EncodeToString(sum))
	return signature, nil
}
