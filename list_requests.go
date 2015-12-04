package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/cloudtools/ssh-cert-authority/util"
	"github.com/codegangsta/cli"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

func listCertFlags() []cli.Flag {
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
		cli.BoolFlag{
			Name:  "show-all",
			Usage: "Show certs that have already been signed as well",
		},
	}
}

func listCerts(c *cli.Context) {

	configPath := c.String("config-file")
	environment := c.String("environment")
	showAll := c.Bool("show-all")

	allConfig := make(map[string]ssh_ca_util.RequesterConfig)
	err := ssh_ca_util.LoadConfig(configPath, &allConfig)
	wrongTypeConfig, err := ssh_ca_util.GetConfigForEnv(environment, &allConfig)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	config := wrongTypeConfig.(ssh_ca_util.RequesterConfig)

	getResp, err := http.Get(config.SignerUrl + "cert/requests")
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
		fmt.Println("Error getting listing of certs", string(getRespBuf))
		os.Exit(1)
	}

	certs := make(certRequestResponse)
	json.Unmarshal(getRespBuf, &certs)
	for requestID, respElement := range certs {
		if showAll || !respElement.Signed {
			rawCert, err := base64.StdEncoding.DecodeString(respElement.CertBlob)
			if err != nil {
				fmt.Println("Trouble base64 decoding response:", err, respElement.CertBlob)
				os.Exit(1)
			}
			pubKey, err := ssh.ParsePublicKey(rawCert)
			if err != nil {
				fmt.Println("Trouble parsing response:", err)
				os.Exit(1)
			}
			cert := *pubKey.(*ssh.Certificate)
			env, ok := cert.Extensions["environment@cloudtools.github.io"]
			if !ok {
				env = "unknown env"
			}
			expired := int64(cert.ValidBefore)-int64(time.Now().Unix()) < 1
			if !expired || showAll {
				expiredMsg := ""
				if expired {
					expiredMsg = ", \033[91mexpired\033[0m"
				}
				fmt.Printf("%d %s[%s, %d/%d%s]: %s - %s\n",
					respElement.Serial,
					requestID,
					env,
					respElement.NumSignatures,
					respElement.SignaturesRequired,
					expiredMsg,
					cert.KeyId,
					cert.Extensions["reason@cloudtools.github.io"],
				)
			}
		}
	}
}
