# Description
This go SDK is designed to help developers easily integrate Onqlave application layer encryption (ALE) into their go backend.

[![CI](https://img.shields.io/static/v1?label=CI&message=passing&color=green?style=plastic&logo=github)](https://github.com/onqlavelabs/onqlave-go/actions)
[![GitHub release](https://img.shields.io/github/v/release/onqlavelabs/onqlave-go.svg)](https://github.com/onqlavelabs/onqlave-go/releases)
[![License](https://img.shields.io/github/license/onqlavelabs/onqlave-go)](https://github.com/onqlavelabs/onqlave-go/blob/main/LICENSE)


# Table of Contents

- [Description](#description)
- [Table of Contents](#table-of-contents)
  - [Features](#features)
  - [Installation](#installation)
    - [Requirements](#requirements)
    - [Configuration](#configuration)
    - [Usage](#usage)
      - [Encrypt](#encrypt)
      - [Decrypt](#decrypt)
  - [Reporting a Vulnerability](#reporting-a-vulnerability)


## Features

- To be done

## Installation

### Requirements
- go 1.18 and above

### Configuration

Make sure your project is using Go Modules (it will have a go.mod file in its root if it already is):

```go
go mod init
```

Then, reference onqlave-go in a Go program with import:

```go
import (
  Onqlave "github.com/onqlavelabs/onqlave-go"
)
```
Alternatively, `go get github.com/onqlavelabs/onqlave-go` can also be used to download the required dependencies

### Usage

To use this SDK, you firstly need to obtain credential to access an Onqlave Arx by signing up to [Onqlave](https://onqlave.com) and following instruction to create your 1st Onqlave Arx.

The [Onqlave Go](https://github.com/onqlavelabs/onqlave-go) module is used to perform operations on the configured ARX such as encrypting, and decrypting for an Onqlave_ARX. [example](https://github.com/onqlavelabs/onqlave-go/blob/main/examples/main.go):

To use this module, the Onqlave client must first be initialized as follows.

```go
import (
     "github.com/onqlavelabs/onqlave-go/onqlave/connection"
	   "github.com/onqlavelabs/onqlave-go/onqlave/credentials"
	   "github.com/onqlavelabs/onqlave-go/onqlave/encryption"
	   "github.com/onqlavelabs/onqlave-go/onqlave/keymanager"
)

configuration := keymanager.Configuration{
		ArxURL: "<arx_url>",                //This is the Arx URL retruned of the API Key created during setup
		Credential: &credentials.Credential{
			AccessKey:  "<api_access_key>",   //This is the API Access Key returned of the API Key created during setup
			SigningKey: "<api_signing_key>",  //This is the API Signing Key retruned of the API Key created during setup
			SecretKey:  "<api_secret_key>",   //This is the API Secret Key retruned of the API Key created during setup
		},
		Retry: &connection.RetrySettings{
			Count:       <count>,         //Number of times to retry calling server endpoints in case connection issue
			WaitTime:    <wiat_time>,     //How long to wait between each retry
			MaxWaitTime: <max_wait_time>, //How long towait in total for operation to finish
		},
}

service := encryption.NewEncryption(&configuration)
defer service.Close()
```

All Onqlave APIs must be invoked using a `Encryption` instance.

### Encrypt

To encrypt data, use the **Encrypt(plainText, associatedData []byte)** method of the `Encryption` service. The **plainText** parameter is the `[]byte` representation of data you are wishing to encrypt. The **associatedData** parameter the `[]byte` representation of associated data which can be used to improve the authenticity of the data (it is not mandatory), as shown below.

Encrypt call:

```go
import (
	"github.com/onqlavelabs/onqlave-go/onqlave/connection"
	"github.com/onqlavelabs/onqlave-go/onqlave/credentials"
	"github.com/onqlavelabs/onqlave-go/onqlave/encryption"
	"github.com/onqlavelabs/onqlave-go/onqlave/keymanager"
)

configuration := keymanager.Configuration{
		ArxURL: "<arx_url>",                //This is the Arx URL retruned of the API Key created during setup
		Credential: &credentials.Credential{
			AccessKey:  "<api_access_key>",   //This is the API Access Key returned of the API Key created during setup
			SigningKey: "<api_signing_key>",  //This is the API Signing Key retruned of the API Key created during setup
			SecretKey:  "<api_secret_key>",   //This is the API Secret Key retruned of the API Key created during setup
		},
		Retry: &connection.RetrySettings{
			Count:       2,                      //Number of times to retry calling server endpoints in case connection issue
			WaitTime:    400 * time.Millisecond, //How long to wait between each retry
			MaxWaitTime: 2 * time.Second,        //How long towait in total for operation to finish
		},
}

//Initialize the Encryption service.
service := encryption.NewEncryption(&configuration)
defer service.Close()

plainData := []byte("this data needs to be encrypted")
associatedData := []byte("this data needs to be authenticated, but not encrypted")
cipherData, err := service.Encrypt(plainData, associatedData)
```


### Decrypt
To encrypt data, use the **Decrypt(cipherData, associatedData []byte)** method of the `Encryption` service. The **cipherData** parameter is the `[]byte` representation of data you are wishing to decrypt (previousely encrypted). The **associatedData** parameter the `[]byte` representation of associated data which can be used to improve the authenticity of the data (it is not mandatory), as shown below.

```go
import (
	"github.com/onqlavelabs/onqlave-go/onqlave/connection"
	"github.com/onqlavelabs/onqlave-go/onqlave/credentials"
	"github.com/onqlavelabs/onqlave-go/onqlave/encryption"
	"github.com/onqlavelabs/onqlave-go/onqlave/keymanager"
)

configuration := keymanager.Configuration{
		ArxURL: "<arx_url>",                //This is the Arx URL retruned of the API Key created during setup
		Credential: &credentials.Credential{
			AccessKey:  "<api_access_key>",   //This is the API Access Key returned of the API Key created during setup
			SigningKey: "<api_signing_key>",  //This is the API Signing Key retruned of the API Key created during setup
			SecretKey:  "<api_secret_key>",   //This is the API Secret Key retruned of the API Key created during setup
		},
		Retry: &connection.RetrySettings{
			Count:       2,                      //Number of times to retry calling server endpoints in case connection issue
			WaitTime:    400 * time.Millisecond, //How long to wait between each retry
			MaxWaitTime: 2 * time.Second,        //How long towait in total for operation to finish
		},
}

//Initialize the Encryption service.
service := encryption.NewEncryption(&configuration)
defer service.Close()

cipherData := []byte("this data is already encrypted using `Encrypt` method")
associatedData := []byte("this data needs to be authenticated, but not encrypted")
plainData, err := service.Decrypt(cipherData, associatedData)
```

## Reporting a Vulnerability

If you discover a potential security issue in this project, please reach out to us at security@onqlave.com. Please do not create public GitHub issues or Pull Requests, as malicious actors could potentially view them.
