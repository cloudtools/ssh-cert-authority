package main

import (
	"github.com/cloudtools/ssh-cert-authority/util"
	"github.com/codegangsta/cli"
	"os"
)

func main() {
	app := cli.NewApp()
	app.Name = "ssh-cert-authority"
	app.EnableBashCompletion = true
	app.Version = ssh_ca_util.BuildVersion

	app.Commands = []cli.Command{
		{
			Name:    "request",
			Aliases: []string{"r"},
			Flags:   requestCertFlags(),
			Usage:   "Request a new certificate",
			Action:  requestCert,
		},
		{
			Name:    "sign",
			Aliases: []string{"s"},
			Flags:   signCertFlags(),
			Usage:   "Sign a certificate",
			Action:  signCert,
		},
		{
			Name:    "get",
			Aliases: []string{"g"},
			Flags:   getCertFlags(),
			Usage:   "Get a certificate",
			Action:  getCert,
		},
		{
			Name:    "list",
			Aliases: []string{"l"},
			Flags:   listCertFlags(),
			Usage:   "List pending requests on the server",
			Action:  listCerts,
		},
		{
			Name:   "runserver",
			Flags:  signdFlags(),
			Usage:  "Run the cert-authority web service",
			Action: signCertd,
		},
		{
			Name:   "encrypt-key",
			Flags:  encryptFlags(),
			Usage:  "Optionally generate and then encrypt an ssh private key",
			Action: cmdEncryptKey,
		},
		{
			Name:   "generate-config",
			Flags:  generateConfigFlags(),
			Usage:  "Try to generate a configuration file for a requester",
			Action: cmdGenerateConfig,
		},
	}
	app.Run(os.Args)
}
