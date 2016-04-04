package main

import (
	"bufio"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/codegangsta/cli"
	"io/ioutil"
	"os"
)

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
	}
}

func encryptKey(c *cli.Context) {
	region, err := ec2metadata.New(session.New(), aws.NewConfig()).Region()
	if err != nil {
		fmt.Printf("Unable to determine our region: %s", err)
		os.Exit(1)
	}
	keyContents, err := ioutil.ReadAll(bufio.NewReader(os.Stdin))
	if err != nil {
		fmt.Printf("Unable to read private key: %s", err)
		os.Exit(1)
	}
	svc := kms.New(session.New(), aws.NewConfig().WithRegion(region))
	params := &kms.EncryptInput{
		Plaintext: keyContents,
		KeyId:     aws.String(c.String("key-id")),
	}
	resp, err := svc.Encrypt(params)
	if err != nil {
		fmt.Printf("Unable to Encrypt CA key: %v\n", err)
		os.Exit(1)
	}
	keyContents = resp.CiphertextBlob
	ioutil.WriteFile(c.String("output"), resp.CiphertextBlob, 0444)
}
