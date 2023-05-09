package onqlaveconnection

import (
	"fmt"
	"strconv"
	"time"

	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavecontracts/requests"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlaveerrors"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavelogger"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavemessages"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlaveutils"
)

const (
	OnqlaveAPIKey        string = "ONQLAVE-API-KEY"
	OnqlaveContent       string = "Content-Type"
	OnqlaveHost          string = "ONQLAVE-HOST"
	OnqlaveVersion       string = "ONQLAVE-VERSION"
	OnqlaveSignature     string = "ONQLAVE-SIGANTURE"
	OnqlaveDigest        string = "ONQLAVE-DIGEST"
	OnqlaveArx           string = "ONQLAVE-ARX"
	OnqlaveAgent         string = "User-Agent"
	OnqlaveRequestTime   string = "ONQLAVE-REQUEST-TIME"
	OnqlaveContentLength string = "ONQLAVE-CONTEXT-LEN"
)

type Connection interface {
	Post(resource string, body requests.OnqlaveRequest) ([]byte, *onqlaveerrors.OnqlaveError)
}

type connection struct {
	client        Client
	hasher        onqlaveutils.Hasher
	logger        *onqlavelogger.Logger
	configuration *Configuration
}

type Configuration struct {
	Credential *Credential
	Retry      *RetrySettings
	ArxURL     string
	ArxID      string
}

type Credential struct {
	AccessKey  string
	SigningKey string
}

func NewConnection(configuration *Configuration, hasher onqlaveutils.Hasher, logger *onqlavelogger.Logger) Connection {
	client := NewClient(configuration.Retry, logger)
	return &connection{client: client, hasher: hasher, logger: logger, configuration: configuration}
}

const (
	ServerType       string = "Onqlave/0.1"
	Version          string = "0.1"
	Oonqlave_Content string = "application/json"
)

func (c *connection) Post(resource string, body requests.OnqlaveRequest) ([]byte, *onqlaveerrors.OnqlaveError) {
	operation := "Post"
	start := time.Now()
	c.logger.Debug(fmt.Sprintf(onqlavemessages.CLIENT_OPERATION_STARTED, operation))
	urlString := fmt.Sprintf("%s/%s", c.configuration.ArxURL, resource)
	arxID := c.configuration.ArxID
	now := time.Now().UTC()
	content, err := body.GetContent()
	if err != nil {
		c.logger.Error(fmt.Sprintf(onqlavemessages.CLIENT_ERROR_EXTRACTING_CONTENT, operation))
		return nil, onqlaveerrors.NewOnqlaveErrorWrapf(onqlaveerrors.Server, err, onqlavemessages.CLIENT_ERROR_EXTRACTING_CONTENT, operation)
	}
	contentLen := len(content)
	digest, err := c.hasher.Digest(body)
	if err != nil {
		c.logger.Error(fmt.Sprintf(onqlavemessages.CLIENT_ERROR_CALCULATING_DIGEST, operation))
		return nil, onqlaveerrors.NewOnqlaveErrorWrapf(onqlaveerrors.Server, err, onqlavemessages.CLIENT_ERROR_CALCULATING_DIGEST, operation)
	}
	headersToSign := map[string]string{
		OnqlaveAPIKey:        c.configuration.Credential.AccessKey,
		OnqlaveArx:           arxID,
		OnqlaveHost:          c.configuration.ArxURL, //to deal with issue of tailing slach added to ARX_URL env on server side
		OnqlaveAgent:         ServerType,
		OnqlaveContentLength: strconv.FormatInt(int64(contentLen), 10),
		OnqlaveDigest:        digest,
		OnqlaveVersion:       Version,
	}
	signature, err := c.hasher.Sign(headersToSign, c.configuration.Credential.SigningKey)
	if err != nil {
		c.logger.Error(fmt.Sprintf(onqlavemessages.CLIENT_ERROR_CALCULATING_SIGNATURE, operation))
		return nil, onqlaveerrors.NewOnqlaveErrorWrapf(onqlaveerrors.Server, err, onqlavemessages.CLIENT_ERROR_CALCULATING_SIGNATURE, operation)
	}
	headers := map[string]string{
		OnqlaveContent:       Oonqlave_Content,
		OnqlaveAPIKey:        c.configuration.Credential.AccessKey,
		OnqlaveArx:           arxID,
		OnqlaveHost:          c.configuration.ArxURL,
		OnqlaveAgent:         ServerType,
		OnqlaveRequestTime:   strconv.FormatInt(now.Unix(), 10),
		OnqlaveContentLength: strconv.FormatInt(int64(contentLen), 10),
		OnqlaveDigest:        digest,
		OnqlaveVersion:       Version,
		OnqlaveSignature:     signature,
	}

	resp, err := c.client.Post(urlString, body, headers)
	if err != nil {
		c.logger.Error(fmt.Sprintf(onqlavemessages.CLIENT_ERROR_PORTING_REQUEST, operation, "HTTP:POST"))
		return nil, onqlaveerrors.NewOnqlaveErrorWrapf(onqlaveerrors.Server, err, onqlavemessages.CLIENT_ERROR_PORTING_REQUEST, operation, "HTTP:POST")
	}
	c.logger.Debug(fmt.Sprintf(onqlavemessages.CLIENT_OPERATION_SUCCESS, operation, time.Since(start)))
	return resp, nil
}
