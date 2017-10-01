package main

import (
	"encoding/json"
	"fmt"
	"github.com/cloudtools/ssh-cert-authority/util"
	"github.com/codegangsta/cli"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

func generateConfigFlags() []cli.Flag {
	home := os.Getenv("HOME")
	if home == "" {
		home = "/"
	}
	return []cli.Flag{
		cli.StringFlag{
			Name:  "url, u",
			Value: "",
			Usage: "An ssh-cert-authority url (e.g. https://ssh-cert-authority.example.com).",
		},
		cli.StringFlag{
			Name:  "key-file, k",
			Value: fmt.Sprintf("%s/.ssh/id_rsa.pub", home),
			Usage: "Path to your SSH public key. The filename will be inserted into the generated config file.",
		},
	}
}

func cmdGenerateConfig(c *cli.Context) error {

	url := c.String("url")
	if url == "" {
		return cli.NewExitError("url is a required option.", 1)
	}
	if !strings.HasSuffix(url, "/") {
		url = url + "/"
	}

	getResp, err := http.Get(url + "config/environments")
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("Didn't get a valid response: %s", err), 1)
	}

	getRespBuf, err := ioutil.ReadAll(getResp.Body)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("Error reading response body: %s", err), 1)
	}
	getResp.Body.Close()
	if getResp.StatusCode != 200 {
		return cli.NewExitError(fmt.Sprintf("Error getting listing of environments: %s", string(getRespBuf)), 1)
	}

	var environments []string
	json.Unmarshal(getRespBuf, &environments)

	wholeConfig := make(map[string]ssh_ca_util.RequesterConfig, len(environments))
	for _, envName := range environments {
		wholeConfig[envName] = ssh_ca_util.RequesterConfig{
			PublicKeyPath: c.String("key-file"),
			SignerUrl:     url,
		}
	}
	result, err := json.MarshalIndent(wholeConfig, "", "    ")
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("Failed to serialize config file: %v", err), 1)
	}
	fmt.Print(string(result))
	return nil
}
