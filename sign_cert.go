package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

func signCertFlags() []cli.Flag {
	home := os.Getenv("HOME")
	if home == "" {
		home = "/"
	}
	configPath := home + "/.ssh_ca/signer_config.json"

	return []cli.Flag{
		cli.StringFlag{
			Name:  "environment",
			Value: "",
			Usage: "An environment name (e.g. prod)",
		},
		cli.StringFlag{
			Name:  "config-file",
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

func signCert(c *cli.Context) {
	configPath := c.String("config-file")
	allConfig := make(map[string]ssh_ca_util.SignerConfig)
	err := ssh_ca_util.LoadConfig(configPath, &allConfig)
	if err != nil {
		fmt.Println("Load Config failed:", err)
		os.Exit(1)
	}

	certRequestID := c.String("cert-request-id")
	if certRequestID == "" {
		certRequestID = c.Args().First()
		if certRequestID == "" {
			fmt.Println("Specify a cert-request-id")
			os.Exit(1)
		}
	}
	environment := c.String("environment")
	wrongTypeConfig, err := ssh_ca_util.GetConfigForEnv(environment, &allConfig)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	config := wrongTypeConfig.(ssh_ca_util.SignerConfig)

	conn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		fmt.Println("Dial failed:", err)
		os.Exit(1)
	}

	signer, err := ssh_ca_util.GetSignerForFingerprint(config.KeyFingerprint, conn)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	requestParameters := make(url.Values)
	requestParameters["certRequestId"] = make([]string, 1)
	requestParameters["certRequestId"][0] = certRequestID
	getResp, err := http.Get(config.SignerUrl + "cert/requests?" + requestParameters.Encode())
	if err != nil {
		fmt.Println("Didn't get a valid response", err)
		os.Exit(1)
	}
	getRespBuf, err := ioutil.ReadAll(getResp.Body)
	if err != nil {
		fmt.Println("Error reading response body", err)
		os.Exit(1)
	}
	getResp.Body.Close()
	if getResp.StatusCode != 200 {
		fmt.Println("Error getting that request id:", string(getRespBuf))
		os.Exit(1)
	}
	getResponse := make(certRequestResponse)
	err = json.Unmarshal(getRespBuf, &getResponse)
	if err != nil {
		fmt.Println("Unable to unmarshall response", err)
		os.Exit(1)
	}
	rawCert, err := base64.StdEncoding.DecodeString(getResponse[certRequestID].CertBlob)
	if err != nil {
		fmt.Println("Trouble base64 decoding response", err)
		os.Exit(1)
	}
	pubKey, err := ssh.ParsePublicKey(rawCert)
	if err != nil {
		fmt.Println("Trouble parsing response", err)
		os.Exit(1)
	}
	cert := *pubKey.(*ssh.Certificate)
	fmt.Printf("This cert is for the %s environment\n", getResponse[certRequestID].Environment)
	fmt.Println("Reason:", getResponse[certRequestID].Reason)
	ssh_ca_util.PrintForInspection(cert)
	fmt.Printf("Type 'yes' if you'd like to sign this cert request ")
	reader := bufio.NewReader(os.Stdin)
	text, _ := reader.ReadString('\n')
	text = strings.TrimSpace(text)
	if text != "yes" && text != "YES" {
		os.Exit(0)
	}

	err = cert.SignCert(rand.Reader, signer)
	if err != nil {
		fmt.Println("Error signing:", err)
		os.Exit(1)
	}

	signedRequest := cert.Marshal()

	requestParameters = make(url.Values)
	requestParameters["cert"] = make([]string, 1)
	requestParameters["cert"][0] = base64.StdEncoding.EncodeToString(signedRequest)
	resp, err := http.PostForm(config.SignerUrl+"cert/requests/"+certRequestID, requestParameters)
	if err != nil {
		fmt.Println("Error sending request to signer daemon:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		fmt.Println("Signature accepted by server.")
	} else {
		fmt.Println("Cert signature not accepted.")
		fmt.Println("HTTP status", resp.Status)
		respBuf, _ := ioutil.ReadAll(resp.Body)
		fmt.Println(string(respBuf))
		os.Exit(1)
	}

}
