package onqlaveconnection

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavecontracts/requests"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlaveerrors"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavelogger"
	"github.com/stretchr/testify/assert"
)

func TestPost(t *testing.T) {
	c := NewClient(&RetrySettings{Count: 3, WaitTime: 500 * time.Millisecond}, onqlavelogger.NewLog("test"))

	t.Run("Successful Post", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte("OK"))
			assert.NoError(t, err)
		}))
		defer ts.Close()

		body := &requests.EncryptionOpenRequest{}
		headers := map[string]string{"header-key": "header-value"}

		response, err := c.Post(ts.URL, body, headers)
		assert.NoError(t, err)
		assert.Equal(t, []byte("OK"), response)
	})

	t.Run("Error Response", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, err := w.Write([]byte(`{"error": {"message": "Bad Request"}}`))
			assert.NoError(t, err)
		}))
		defer ts.Close()

		body := &requests.EncryptionOpenRequest{}
		headers := map[string]string{"header-key": "header-value"}

		response, err := c.Post(ts.URL, body, headers)
		assert.Nil(t, response)
		assert.Error(t, err)
		assert.IsType(t, &onqlaveerrors.OnqlaveError{}, err)
	})

	t.Run("Retry Policy", func(t *testing.T) {
		var callCount int
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			if callCount <= 2 {
				w.WriteHeader(http.StatusInternalServerError)
			} else {
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte("OK"))
				assert.NoError(t, err)
			}
		}))
		defer ts.Close()

		body := &requests.EncryptionOpenRequest{}
		headers := map[string]string{"header-key": "header-value"}

		response, err := c.Post(ts.URL, body, headers)
		assert.NoError(t, err)
		assert.Equal(t, []byte("OK"), response)
	})
}
