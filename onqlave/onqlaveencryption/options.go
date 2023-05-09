package onqlaveencryption

import (
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlaveconnection"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavecredentials"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavekeymanager"
)

type Option interface {
	apply(*onqlavekeymanager.Configuration)
}

type credentialOption struct {
	credential *onqlavecredentials.Credential
}

type retryOption struct {
	retry *onqlaveconnection.RetrySettings
}

type arxOption struct {
	arxURL string
}

type debugOption struct {
	debug bool
}

func (opts *debugOption) apply(c *onqlavekeymanager.Configuration) {
	c.Debug = opts.debug
}

func (opts *arxOption) apply(c *onqlavekeymanager.Configuration) {
	c.ArxURL = opts.arxURL
}

func (opts *credentialOption) apply(c *onqlavekeymanager.Configuration) {
	c.Credential = opts.credential
}

func (opts *retryOption) apply(c *onqlavekeymanager.Configuration) {
	c.Retry = opts.retry
}

func WithCredential(c onqlavecredentials.Credential) Option {
	return &credentialOption{
		credential: &c,
	}
}

func WithRetry(r onqlaveconnection.RetrySettings) Option {
	return &retryOption{
		retry: &r,
	}
}

func WithDebug(debug bool) Option {
	return &debugOption{
		debug: debug,
	}
}

const (
	INVALID_ARX string = "invalid_arx"
)

func WithArx(a string) Option {
	return &arxOption{
		arxURL: a,
	}
}
