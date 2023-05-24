# Description
This go SDK is designed to help developers easily integrate Onqlave `Encryption As A Service` into their go backend.

[![CI](https://img.shields.io/static/v1?label=CI&message=passing&color=green?style=plastic&logo=github)](https://github.com/onqlavelabs/onqlave-go/actions)
[![GitHub release](https://img.shields.io/github/v/release/onqlavelabs/onqlave-go.svg)](https://github.com/onqlavelabs/onqlave-go/releases)
[![License](https://img.shields.io/github/license/onqlavelabs/onqlave-go)](https://github.com/onqlavelabs/onqlave-go/blob/main/LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/onqlavelabs/onqlave-go.svg)](https://pkg.go.dev/github.com/onqlavelabs/onqlave-go)

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
		- [Encrypt Stream](#encrypt-stream)
		- [Decrypt Stream](#decrypt-stream)
	- [Reporting a Vulnerability](#reporting-a-vulnerability)

## Features

- Encrypt/Decrypt piece of information
- Encrypt/Decrypt stream of data

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
  onqlave "github.com/onqlavelabs/onqlave-go"
)
```
Alternatively, `go get github.com/onqlavelabs/onqlave-go` can also be used to download the required dependencies

### Usage

To use this SDK, you firstly need to obtain credential to access an Onqlave Arx by signing up to [Onqlave](https://onqlave.com) and following instruction to create your 1st Onqlave Arx. Documentation can be found at [Onqlave Technical Documentation](https://docs.onqlave.com).

The [Onqlave Go](https://github.com/onqlavelabs/onqlave-go) module is used to perform operations on the configured ARX such as encrypting, and decrypting for an Onqlave_ARX. [example](https://github.com/onqlavelabs/onqlave-go/blob/main/examples/main.go):

To use this module, the Onqlave client must first be initialized as follows.

```go
import (
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlaveconnection"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavecredentials"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlaveencryption"
)

debugOption := onqlaveencryption.WithDebug(true) //This option lets you choose whether to start SDK operation in debug mode to info mode
arxOption := onqlaveencryption.WithArx("<arx_url>") //This is the Arx URL retruned of the API Key created during setup. Keep in in a safe place.
credentialOption := onqlaveencryption.WithCredential(onqlavecredentials.Credential{
	AccessKey:  "<api_access_key>",   //This is the API Access Key returned of the API Key created during setup. Keep in in a safe place.
	SigningKey: "<api_signing_key>",  //This is the API Signing Key retruned of the API Key created during setup. Keep in in a safe place.
	SecretKey:  "<api_secret_key>",   //This is the API Secret Key retruned of the API Key created during setup. Keep in in a safe place.
})
retryOption := onqlaveencryption.WithRetry(onqlaveconnection.RetrySettings{
	Count:       <count>,         //Number of times to retry calling server endpoints in case of connection issue
	WaitTime:    <wait_time>,     //How long to wait between each retry
	MaxWaitTime: <max_wait_time>, //How long to wait in total for operation to finish
})

service := encryption.NewEncryption(debugOption, arxOption, credentialOption, retryOption)
defer service.Close()
```

All Onqlave APIs must be invoked using a `Encryption` instance.

### Encrypt

To encrypt data, use the **Encrypt(plainText, associatedData []byte)** method of the `Encryption` service. The **plainText** parameter is the `[]byte` representation of data you are wishing to encrypt. The **associatedData** parameter the `[]byte` representation of associated data which can be used to improve the authenticity of the data (it is not mandatory), as shown below.

Encrypt call:

```go

//Initilise the new encryption service using configurations as per [Usage]
service := encryption.NewEncryption(debugOption, arxOption, credentialOption, retryOption)
defer service.Close()

plainData := []byte("this data needs to be encrypted")
associatedData := []byte("this data needs to be authenticated, but not encrypted") //This can be an arbitrary piece of information you can use to for added security purpose.
cipherData, err := service.Encrypt(plainData, associatedData)
```


### Decrypt
To decrypt data, use the **Decrypt(cipherData, associatedData []byte)** method of the `Encryption` service. The **cipherData** parameter is the `[]byte` representation of data you are wishing to decrypt (previousely encrypted). The **associatedData** parameter the `[]byte` representation of associated data which can be used to improve the authenticity of the data (it is not mandatory), as shown below.

```go

//Initilise the new encryption service using configurations as per [Usage]
service := encryption.NewEncryption(debugOption, arxOption, credentialOption, retryOption)
defer service.Close()

cipherData := []byte("this data is already encrypted using `Encrypt` method")
associatedData := []byte("this data needs to be authenticated, but not encrypted") //This can be an arbitrary piece of information you can use to for added security purpose.
plainData, err := service.Decrypt(cipherData, associatedData)
```

### Encrypt Stream

To encrypt stream of data, use the **EncryptStream(plainStream io.Reader, cipherStream io.Writer, associatedData []byte)** method of the `Encryption` service. The **plainStream** parameter is the `io.Reader` stream of data you are wishing to encrypt. The **cipherStream** parameter is the `io.Write` stream you are wishing to write the cipher data to. The **associatedData** parameter the `[]byte` representation of associated data which can be used to improve the authenticity of the data (it is not mandatory), as shown below.

```go

//Initilise the new encryption service using configurations as per [Usage]
service := encryption.NewEncryption(debugOption, arxOption, credentialOption, retryOption)
defer service.Close()

plainStream, _ := os.OpenFile("<file or network stream you are wishing to encrypt>", os.O_RDONLY, 0666)
associatedData := []byte("this data needs to be authenticated, but not encrypted") //This can be an arbitrary piece of information you can use to for added security purpose.
cipherStream,_ := os.OpenFile("<file or network stream you are whishing to stream the encrypted data to>", os.O_WRONLY, 0666)
err := service.EncryptStream(plainStream, cipherStream, associatedData)
```


### Decrypt Stream
To decrypt data, use the **DecryptStream(cipherStream io.Reader, plainStream io.Writer, associatedData []byte)** method of the `Encryption` service. The **cipherStream** parameter is the `io.Reader` stream of data you are wishing to decrypt and it was originally encrypted using [EncryptStream](#encrypt-stream). The **plainStream** parameter is the `io.Write` stream you are wishing to write the plain data back to. The **associatedData** parameter the `[]byte` representation of associated data which can be used to improve the authenticity of the data (it is not mandatory), as shown below.

```go

//Initilise the new encryption service using configurations as per [Usage]
service := encryption.NewEncryption(debugOption, arxOption, credentialOption, retryOption)
defer service.Close()

cipherStream, _ := os.OpenFile("<file or network stream you are wishing to decrypt>", os.O_RDONLY, 0666)
associatedData := []byte("this data needs to be authenticated, but not encrypted") //This can be an arbitrary piece of information you can use to for added security purpose.
plainStream,_ := os.OpenFile("<file or network stream you are whishing to stream the decrypted data to>", os.O_WRONLY, 0666)
err := service.DecryptStreamcipherStream, plainStream, associatedData)
```

## Reporting a Vulnerability

If you discover a potential security issue in this project, please reach out to us at security@onqlave.com. Please do not create public GitHub issues or Pull Requests, as malicious actors could potentially view them.
