package examples

import (
	"bytes"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/onqlavelabs/onqlave-go/onqlave/onqlaveconnection"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlavecredentials"
	"github.com/onqlavelabs/onqlave-go/onqlave/onqlaveencryption"
)

func encryption_cycle(opts ...onqlaveencryption.Option) {
	service := onqlaveencryption.NewEncryption(opts...)
	defer service.Close()
	test := "This is a test plaintext"
	cipher, err := service.Encrypt([]byte(test), nil)
	if err != nil {
		fmt.Printf("Error happend in encrypting: %s", err)
	} else {
		plainData, err := service.Decrypt(cipher, nil)
		if err != nil || string(plainData) != test {
			fmt.Printf("Error happend in decrypting: %s", err)
		}
	}
}

func encryption_cycle_file(opts ...onqlaveencryption.Option) {
	service := onqlaveencryption.NewEncryption(opts...)
	path, _ := os.Getwd()
	defer service.Close()
	//open your inpu file here - this is the file you would like to ecnrypt - it can be any implementation if <io.Reader> interface
	plainStream, err := os.OpenFile(path+"/examples/data.in", os.O_RDONLY, 0666)
	if err != nil {
		fmt.Printf("Error happend in opening file: %s", err)
		return
	}
	//this is the output stream where you would like to write the cipther to - it can be any implementation of <io.Writer> interface
	cipherStream := bytes.NewBuffer(nil)
	er := service.EncryptStream(plainStream, cipherStream, nil)
	if er != nil {
		fmt.Printf("Error happend in encrypting: %s", er)
	} else {
		replainStream, err := os.OpenFile(path+"/examples/data.o", os.O_WRONLY, 0666)
		if err != nil {
			fmt.Printf("Error happend in opening file: %s", err)
			return
		}
		er = service.DecryptStream(cipherStream, replainStream, nil)
		if er != nil {
			fmt.Printf("Error happend in decrypting: %s", er)
		}
		replainStream.Close()
	}

}

func Start() {
	//This option lets you choose whether to start SDK operation in debug mode to info mode
	debugOption := onqlaveencryption.WithDebug(true)
	directory, _ := os.Getwd()

	//This is just for testing purpose - for prodcution environment you must not store your Onqlave keys in file. Best way to handle keys is to keep them in secret manager of your choice!
	credentials, err := LoadCredentials(directory + "/examples/credential.json")
	if err != nil {
		fmt.Printf("Error happend during loading credential file : %s", err)
		return
	}
	options := make([][]onqlaveencryption.Option, len(credentials))
	//This option lets you choose what strategy SDK uses whilst connecting to services in case there is a connectivity issue
	retryOption := onqlaveencryption.WithRetry(onqlaveconnection.RetrySettings{
		Count:       2,
		WaitTime:    400 * time.Millisecond,
		MaxWaitTime: 2 * time.Second,
	})

	//Set the options by credentials read from file/environment/secret manager
	for i, credential := range credentials {
		arxOption := onqlaveencryption.WithArx(credential.Arx)
		credentialOption := onqlaveencryption.WithCredential(onqlavecredentials.Credential{
			AccessKey:  credential.AccessKey,
			SigningKey: credential.SigningKey,
			SecretKey:  credential.SecretKey,
		})
		options[i] = make([]onqlaveencryption.Option, 0)
		options[i] = append(options[i], arxOption, credentialOption, retryOption, debugOption)
	}

	//Concurrent calls to Onqlave services - using SDK
	var wg sync.WaitGroup
	for i := 0; i < len(credentials); i++ {
		wg.Add(1)
		go func(opts ...onqlaveencryption.Option) {
			for {
				encryption_cycle(opts...)
				time.Sleep(300 * time.Millisecond)
				encryption_cycle_file(opts...)
				time.Sleep(30 * time.Millisecond)
			}
		}(options[i]...)
	}
	wg.Wait()
}
