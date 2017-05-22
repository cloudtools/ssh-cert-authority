package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/codegangsta/cli"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"os"
	"regexp"
)

// If you update this regex know that despite my naming the match groups it's
// the order that matters. See uses of keyIdRegex in this file and update
// accordingly.
var keyIdRegex = regexp.MustCompile("arn:aws:kms:(?P<region>[^:]+):(?P<accountid>[^:]+):(?P<keyname>[^:]+)")

func encryptFlags() []cli.Flag {
	return []cli.Flag{
		cli.StringFlag{
			Name:  "key-id",
			Value: "",
			Usage: "The ARN of the KMS key to use",
		},
		cli.StringFlag{
			Name:  "output",
			Value: "ca-key.kms",
			Usage: "The filename for key output",
		},
		cli.BoolFlag{
			Name:  "generate-ecdsa",
			Usage: "When set generate an ECDSA key from Curve P384",
		},
		cli.BoolFlag{
			Name:  "generate-rsa",
			Usage: "When set generate a 4096 bit RSA key",
		},
	}
}

func generateRsa() ([]byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}
	derBlock := x509.MarshalPKCS1PrivateKey(key)
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derBlock,
	}
	return pem.EncodeToMemory(pemBlock), nil
}

func generateEcdsa() ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	derBlock, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	pemBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: derBlock,
	}
	return pem.EncodeToMemory(pemBlock), nil
}

func cmdEncryptKey(c *cli.Context) error {
	var err error
	keyId := c.String("key-id")
	regexResults := keyIdRegex.FindStringSubmatch(keyId)
	if regexResults == nil {
		return cli.NewExitError("--key-id doesn't look like an AWS KMS ARN.", 1)
	}
	region := regexResults[1]

	var ciphertext []byte
	if c.Bool("generate-ecdsa") || c.Bool("generate-rsa") {
		var key []byte
		if c.Bool("generate-ecdsa") {
			key, err = generateEcdsa()
		} else {
			key, err = generateRsa()
		}
		if err != nil {
			return cli.NewExitError(fmt.Sprintf("Unable to generate key: %s", err), 1)
		}
		ciphertext, err = encryptKey(key, region, keyId)
		if err != nil {
			return cli.NewExitError(fmt.Sprintf("Unable to generate ecdsa key: %s", err), 1)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return cli.NewExitError(fmt.Sprintf("Unable to parse generated private key: %s", err), 1)
		}
		err = ioutil.WriteFile(c.String("output")+".pub", ssh.MarshalAuthorizedKey(signer.PublicKey()), 0644)
		if err != nil {
			return cli.NewExitError(fmt.Sprintf("Unable to write new public key: %s", err), 1)
		}
	} else {
		ciphertext, err = encryptKeyFromStdin(keyId, region)
		if err != nil {
			return cli.NewExitError(fmt.Sprintf("Failed to encrypt key: %s", err), 1)
		}
	}
	err = ioutil.WriteFile(c.String("output"), ciphertext, 0644)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("Unable to write new encrypted private key: %s", err), 1)
	}
	return nil
}

func encryptKeyFromStdin(keyId, region string) ([]byte, error) {
	keyContents, err := ioutil.ReadAll(bufio.NewReader(os.Stdin))
	if err != nil {
		return nil, cli.NewExitError(fmt.Sprintf("Unable to read private key: %s", err), 1)
	}
	return encryptKey(keyContents, region, keyId)
}

func encryptKey(plaintextKey []byte, region, kmsKeyId string) ([]byte, error) {
	svc := kms.New(session.New(), aws.NewConfig().WithRegion(region))
	params := &kms.EncryptInput{
		Plaintext: plaintextKey,
		KeyId:     aws.String(kmsKeyId),
	}
	resp, err := svc.Encrypt(params)
	if err != nil {
		return nil, fmt.Errorf("Unable to Encrypt CA key: %v\n", err)
	}
	return []byte(resp.CiphertextBlob), nil
}
