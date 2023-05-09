package onqlavecredentials

import "fmt"

type Credential struct {
	AccessKey  string
	SigningKey string
	SecretKey  string
}

func (c *Credential) Valid() error {
	if c.AccessKey == "" {
		return fmt.Errorf("accesskey is not valid")
	}
	if c.SecretKey == "" {
		return fmt.Errorf("secretkey is not valid")
	}
	if c.SigningKey == "" {
		return fmt.Errorf("signingkey is not valid")
	}
	return nil
}
