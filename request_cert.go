package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"github.com/cloudtools/ssh-cert-authority/client"
	"github.com/cloudtools/ssh-cert-authority/util"
	"github.com/codegangsta/cli"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"time"
)

func trueOnError(err error) uint {
	if err != nil {
		fmt.Println(err)
		return 1
	}
	return 0
}

func requestCertFlags() []cli.Flag {
	validBeforeDur, _ := time.ParseDuration("2h")
	validAfterDur, _ := time.ParseDuration("-2m")
	home := os.Getenv("HOME")
	if home == "" {
		home = "/"
	}
	configPath := home + "/.ssh_ca/requester_config.json"

	return []cli.Flag{
		cli.StringFlag{
			Name:  "principals, p",
			Value: "ec2-user,ubuntu",
			Usage: "Valid usernames for login, comma separated (e.g. ec2-user,ubuntu)",
		},
		cli.StringFlag{
			Name:  "environment, e",
			Value: "",
			Usage: "An environment name (e.g. prod)",
		},
		cli.StringFlag{
			Name:  "config-file, c",
			Value: configPath,
			Usage: "Path to config.json",
		},
		cli.StringFlag{
			Name:  "reason, r",
			Value: "",
			Usage: "Your reason for needing this SSH certificate.",
		},
		cli.DurationFlag{
			Name:  "valid-after",
			Value: validAfterDur,
			Usage: "Relative time",
		},
		cli.DurationFlag{
			Name:  "valid-before",
			Value: validBeforeDur,
			Usage: "Relative time",
		},
		cli.BoolFlag{
			Name:  "quiet",
			Usage: "Print only the request id on success",
		},
		cli.BoolFlag{
			Name:  "add-key",
			Usage: "When set automatically call ssh-add if cert was auto-signed by server",
		},
		cli.StringFlag{
			Name:  "ssh-dir",
			Value: os.Getenv("HOME") + "/.ssh",
			Usage: "Directory where SSH identity files (like 'id_rsa') reside",
		},
	}
}

func requestCert(c *cli.Context) error {
	allConfig := make(map[string]ssh_ca_util.RequesterConfig)
	configPath := c.String("config-file")
	sshDir := c.String("ssh-dir")
	err := ssh_ca_util.LoadConfig(configPath, &allConfig)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("Load Config failed: %s", err), 1)
	}

	environment := c.String("environment")
	wrongTypeConfig, err := ssh_ca_util.GetConfigForEnv(environment, &allConfig)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("%s", err), 1)
	}
	config := wrongTypeConfig.(ssh_ca_util.RequesterConfig)

	reason := c.String("reason")
	if reason == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Please give a reason: ")
		reason, _ = reader.ReadString('\n')
		reason = strings.TrimSpace(reason)
	}
	if reason == "" {
		return cli.NewExitError("Failed to give a reason", 1)
	}

	caRequest := ssh_ca_client.MakeCertRequest()
	caRequest.SetConfig(config)
	failed := trueOnError(caRequest.SetEnvironment(environment))
	failed |= trueOnError(caRequest.SetReason(reason))
	failed |= trueOnError(caRequest.SetValidAfter(c.Duration("valid-after")))
	failed |= trueOnError(caRequest.SetValidBefore(c.Duration("valid-before")))
	failed |= trueOnError(caRequest.SetPrincipalsFromString(c.String("principals")))

	if failed == 1 {
		return cli.NewExitError("One or more errors found. Aborting request.", 1)
	}

	var chosenKeyFingerprint, pubKeyComment string
	var pubKey ssh.PublicKey
	if config.PublicKeyPath != "" {
		pubKeyContents, err := ioutil.ReadFile(config.PublicKeyPath)
		if err != nil {
			return cli.NewExitError(fmt.Sprintf("Trouble opening your public key file %s: %s", config.PublicKeyPath, err), 1)
		}
		pubKey, pubKeyComment, _, _, err = ssh.ParseAuthorizedKey(pubKeyContents)
		if err != nil {
			return cli.NewExitError(fmt.Sprintf("Trouble parsing your public key: %s", err), 1)
		}
		chosenKeyFingerprint = ssh_ca_util.MakeFingerprint(pubKey.Marshal())
	} else {
		chosenKeyFingerprint = config.PublicKeyFingerprint
		pubKeyComment = "unknown"
	}

	if chosenKeyFingerprint == "" {
		return cli.NewExitError("No SSH fingerprint found. Try setting PublicKeyFingerprint in requester config.", 1)
	}

	conn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("Dial failed: %s", err), 1)
	}

	signer, err := ssh_ca_util.GetSignerForFingerprint(chosenKeyFingerprint, conn)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("%s", err), 1)
	}
	switch signer.PublicKey().Type() {
	case ssh.KeyAlgoRSA, ssh.KeyAlgoDSA, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoED25519:
	default:
		return cli.NewExitError(fmt.Sprintf("Unsupported ssh key type: %s\nWe support rsa, dsa, edd25519 and ecdsa. Need golang support for other algorithms.", signer.PublicKey().Type()), 1)
	}

	caRequest.SetPublicKey(signer.PublicKey(), pubKeyComment)
	newCert, err := caRequest.EncodeAsCertificate()
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("Error encoding certificate request: %s", err), 1)
	}
	err = newCert.SignCert(rand.Reader, signer)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("Error signing: %s", err), 1)
	}

	certRequest := newCert.Marshal()
	requestParameters := caRequest.BuildWebRequest(certRequest)
	requestID, signed, err := caRequest.PostToWeb(requestParameters)
	if err == nil {
		if c.Bool("quiet") {
			fmt.Println(requestID)
		} else {
			var appendage string
			if signed {
				appendage = " auto-signed"
			}
			fmt.Printf("Cert request id: %s%s\n", requestID, appendage)
			if signed && c.Bool("add-key") {
				cert, err := downloadCert(config, requestID, sshDir)
				if err != nil {
					return cli.NewExitError(fmt.Sprintf("%s", err), 1)
				}
				err = addCertToAgent(cert, sshDir)
				if err != nil {
					return cli.NewExitError(fmt.Sprintf("%s", err), 1)
				}
			}
		}
	} else {
		return cli.NewExitError(fmt.Sprintf("%s", err), 1)
	}
	return nil
}
