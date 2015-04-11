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
			Name:    "runserver",
			Aliases: []string{"g"},
			Flags:   signdFlags(),
			Usage:   "Get a certificate",
			Action:  signCertd,
		},
	}
	app.Run(os.Args)
}
