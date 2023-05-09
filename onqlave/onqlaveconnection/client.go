package onqlaveconnection

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavecontracts/requests"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavecontracts/responses"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlaveerrors"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavelogger"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavemessages"
)

type Client interface {
	Post(resource string, body requests.OnqlaveRequest, headers map[string]string) ([]byte, error)
}

var DefaultRetrySettings *RetrySettings = &RetrySettings{
	Count:       3,
	WaitTime:    400 * time.Millisecond,
	MaxWaitTime: 2000 * time.Millisecond,
}

type RetrySettings struct {
	Count       int
	WaitTime    time.Duration
	MaxWaitTime time.Duration
}

func (s *RetrySettings) Valid() error {
	if s.Count <= 0 {
		return fmt.Errorf("invalid retry count")
	}
	if s.WaitTime.Milliseconds() <= 0 {
		return fmt.Errorf("invalid wait time")
	}
	return nil
}

type client struct {
	logger        *onqlavelogger.Logger
	client        *http.Client
	retrySettings *RetrySettings
}

func NewClient(retrySettings *RetrySettings, logger *onqlavelogger.Logger) Client {
	c := &http.Client{}
	return &client{client: c, logger: logger, retrySettings: retrySettings}
}

func (c *client) Post(resource string, body requests.OnqlaveRequest, headers map[string]string) ([]byte, error) {
	operation := "Http"
	c.logger.Debug(fmt.Sprintf(onqlavemessages.HTTP_OPERATION_STARTED, operation))
	start := time.Now()

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, resource, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}

	for hdrName, hdrValue := range headers {
		req.Header.Set(hdrName, hdrValue)
	}

	resp, err := c.doRequestWithRetry(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 {
		return nil, onqlaveerrors.NewOnqlaveError(onqlaveerrors.SdkErrorCode, resp.Status)
	} else if resp.StatusCode >= 400 {
		var baseError responses.BaseErrorResponse
		err := json.NewDecoder(resp.Body).Decode(&baseError)
		if err == nil {
			return nil, onqlaveerrors.NewOnqlaveError(onqlaveerrors.SdkErrorCode, baseError.Error.Message)
		} else {
			return nil, onqlaveerrors.NewOnqlaveError(onqlaveerrors.SdkErrorCode, err.Error())
		}
	}

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	c.logger.Debug(fmt.Sprintf(onqlavemessages.HTTP_OPERATION_SUCCESS, operation, time.Since(start)))
	return responseBody, nil
}

func (c *client) doRequestWithRetry(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error

	for i := 0; i < c.retrySettings.Count; i++ {
		resp, err = c.client.Do(req)
		if err == nil && resp.StatusCode < 500 {
			return resp, nil
		}
		time.Sleep(c.retrySettings.MaxWaitTime)
	}

	return resp, err
}
