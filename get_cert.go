package main

import (
	"bytes"
	"fmt"
	"github.com/cloudtools/ssh-cert-authority/util"
	"github.com/codegangsta/cli"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

func getCertFlags() []cli.Flag {
	home := os.Getenv("HOME")
	if home == "" {
		home = "/"
	}
	configPath := home + "/.ssh_ca/requester_config.json"

	return []cli.Flag{
		cli.StringFlag{
			Name:  "environment, e",
			Value: "",
			Usage: "An environment name (e.g. prod)",
		},
		cli.StringFlag{
			Name:  "config-file",
			Value: configPath,
			Usage: "Path to config.json",
		},
		cli.BoolTFlag{
			Name:  "add-key",
			Usage: "When set automatically call ssh-add",
		},
		cli.StringFlag{
			Name:  "ssh-dir",
			Value: os.Getenv("HOME") + "/.ssh",
			Usage: "Directory where SSH identity files (like 'id_rsa') reside",
		},
	}
}

func getCert(c *cli.Context) error {

	configPath := c.String("config-file")
	environment := c.String("environment")
	sshDir := c.String("ssh-dir")
	certRequestID := c.Args().First()

	allConfig := make(map[string]ssh_ca_util.RequesterConfig)
	err := ssh_ca_util.LoadConfig(configPath, &allConfig)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("%s", err), 1)
	}
	wrongTypeConfig, err := ssh_ca_util.GetConfigForEnv(environment, &allConfig)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("%s", err), 1)
	}
	config := wrongTypeConfig.(ssh_ca_util.RequesterConfig)
	cert, err := downloadCert(config, certRequestID, sshDir)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("%s", err), 1)
	}
	if c.BoolT("add-key") {
		err = addCertToAgent(cert, sshDir)
		if err != nil {
			return cli.NewExitError(fmt.Sprintf("%s", err), 1)
		}
	}
	return nil
}

func addCertToAgent(cert *ssh.Certificate, sshDir string) error {
	secondsRemaining := int64(cert.ValidBefore) - int64(time.Now().Unix())
	if secondsRemaining < 1 {
		return fmt.Errorf("This certificate has already expired.")
	}
	pubKeyPath, err := findKeyLocally(cert.Key, sshDir)
	privKeyPath := strings.Replace(pubKeyPath, ".pub", "", 1)
	fmt.Printf("pubkey %s, privkey %s\n", pubKeyPath, privKeyPath)
	cmd := exec.Command("ssh-add", "-t", fmt.Sprintf("%d", secondsRemaining), privKeyPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("Error in ssh-add: %s", err)
	}
	return nil
}

func downloadCert(config ssh_ca_util.RequesterConfig, certRequestID string, sshDir string) (*ssh.Certificate, error) {
	getResp, err := http.Get(config.SignerUrl + "cert/requests/" + certRequestID)
	if err != nil {
		return nil, fmt.Errorf("Didn't get a valid response: %s", err)
	}
	getRespBuf, err := ioutil.ReadAll(getResp.Body)
	if err != nil {
		return nil, fmt.Errorf("Error reading response body: %s", err)
	}
	getResp.Body.Close()
	if getResp.StatusCode != 200 {
		return nil, fmt.Errorf("Error getting that request id: %s", string(getRespBuf))
	}

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(getRespBuf)
	if err != nil {
		return nil, fmt.Errorf("Trouble parsing response: %s", err)
	}
	cert := pubKey.(*ssh.Certificate)

	pubKeyPath, err := findKeyLocally(cert.Key, sshDir)

	if err != nil {
		return nil, err
	}
	pubKeyPath = strings.Replace(pubKeyPath, ".pub", "-cert.pub", 1)
	err = ioutil.WriteFile(pubKeyPath, getRespBuf, 0644)
	if err != nil {
		fmt.Printf("Couldn't write certificate file to %s: %s\n", pubKeyPath, err)
	}

	ssh_ca_util.PrintForInspection(*cert)
	return cert, nil
}

func findKeyLocally(key ssh.PublicKey, sshDir string) (string, error) {
	dirEntries, err := ioutil.ReadDir(sshDir)
	if err != nil {
		return "", fmt.Errorf("Could not read your .ssh directory %s: %s\n", sshDir, err)
	}
	for idx := range dirEntries {
		entry := dirEntries[idx]
		if strings.HasSuffix(entry.Name(), ".pub") {
			pubKeyPath := sshDir + "/" + entry.Name()
			pubBuf, err := ioutil.ReadFile(pubKeyPath)
			if err != nil {
				fmt.Printf("Trouble reading public key %s: %s\n", pubKeyPath, err)
				continue
			}
			pubKey, _, _, _, err := ssh.ParseAuthorizedKey(pubBuf)
			if err != nil {
				fmt.Printf("Trouble parsing public key %s (might be unsupported format): %s\n", pubKeyPath, err)
				continue
			}
			if bytes.Equal(pubKey.Marshal(), key.Marshal()) {
				return pubKeyPath, nil
			}
		}
	}
	return "", fmt.Errorf("Couldn't find ssh key for cert.\n")
}
