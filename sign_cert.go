package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/cloudtools/ssh-cert-authority/client"
	"github.com/cloudtools/ssh-cert-authority/util"
	"github.com/codegangsta/cli"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type OperationKind string

const (
	OperationApprove OperationKind = "approve"
	OperationReject  OperationKind = "reject"
)

func signCertFlags() []cli.Flag {
	home := os.Getenv("HOME")
	if home == "" {
		home = "/"
	}
	configPath := home + "/.ssh_ca/signer_config.json"

	return []cli.Flag{
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
			Name:  "cert-request-id",
			Value: "",
			Usage: "The certificate request id to look at. Also works as a positional argument.",
		},
	}
}

func signCert(c *cli.Context) error {
	configPath := c.String("config-file")
	allConfig := make(map[string]ssh_ca_util.SignerConfig)
	err := ssh_ca_util.LoadConfig(configPath, &allConfig)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("Load Config failed: %s", err), 1)
	}

	certRequestID := c.String("cert-request-id")
	if certRequestID == "" {
		certRequestID = c.Args().First()
		if certRequestID == "" {
			return cli.NewExitError("Specify a cert-request-id", 1)
		}
	}
	environment := c.String("environment")
	wrongTypeConfig, err := ssh_ca_util.GetConfigForEnv(environment, &allConfig)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("%s", err), 1)
	}
	config := wrongTypeConfig.(ssh_ca_util.SignerConfig)

	conn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("Dial failed: %s", err), 1)
	}

	signer, err := ssh_ca_util.GetSignerForFingerprint(config.KeyFingerprint, conn)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("%s", err), 1)
	}

	requestParameters := make(url.Values)
	requestParameters["certRequestId"] = make([]string, 1)
	requestParameters["certRequestId"][0] = certRequestID
	getResp, err := http.Get(config.SignerUrl + "cert/requests?" + requestParameters.Encode())
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("Didn't get a valid response: %s", err), 1)
	}
	getRespBuf, err := ioutil.ReadAll(getResp.Body)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("Error reading response body: %s", err), 1)
	}
	getResp.Body.Close()
	if getResp.StatusCode != 200 {
		return cli.NewExitError(fmt.Sprintf("Error getting that request id: %s", string(getRespBuf)), 1)
	}
	getResponse := make(certRequestResponse)
	err = json.Unmarshal(getRespBuf, &getResponse)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("Unable to unmarshall response: %s", err), 1)
	}
	if getResponse[certRequestID].Signed {
		return cli.NewExitError("Certificate already signed. Thanks for trying.", 1)
	}
	rawCert, err := base64.StdEncoding.DecodeString(getResponse[certRequestID].CertBlob)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("Trouble base64 decoding response: %s", err), 1)
	}
	pubKey, err := ssh.ParsePublicKey(rawCert)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("Trouble parsing response: %s", err), 1)
	}
	cert := *pubKey.(*ssh.Certificate)
	ssh_ca_util.PrintForInspection(cert)
	fmt.Printf("Type 'yes' if you'd like to sign this cert request, 'reject' to reject it, anything else to cancel ")
	reader := bufio.NewReader(os.Stdin)
	text, _ := reader.ReadString('\n')
	text = strings.TrimSpace(text)
	if text != "yes" && text != "reject" {
		return cli.NewExitError("", 0)
	}
	var operation OperationKind
	if text == "yes" {
		operation = OperationApprove
	} else {
		operation = OperationReject
	}

	err = cert.SignCert(rand.Reader, signer)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("Error signing: %s", err), 1)
	}

	request := ssh_ca_client.MakeSigningRequest(cert, certRequestID, config)
	requestWebParameters := request.BuildWebRequest()
	if operation == OperationApprove {
		err = request.PostToWeb(requestWebParameters)
	} else {
		err = request.DeleteToWeb(requestWebParameters)
	}
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("Error sending in +1: %s", err), 1)
	}
	fmt.Println("Signature accepted by server.")
	return nil

}
