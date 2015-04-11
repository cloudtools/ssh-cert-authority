package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"github.com/cloudtools/ssh-cert-authority/client"
	"github.com/cloudtools/ssh-cert-authority/util"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"io/ioutil"
	"net"
	"os"
	"time"
)

func trueOnError(err error) uint {
	if err != nil {
		fmt.Println(err)
		return 1
	}
	return 0
}

func main() {
	var principalsStr, environment, reason string
	var validBeforeDur, validAfterDur time.Duration

	home := os.Getenv("HOME")
	if home == "" {
		home = "/"
	}
	configPath := home + "/.ssh_ca/requester_config.json"

	validBeforeDur, _ = time.ParseDuration("2h")
	validAfterDur, _ = time.ParseDuration("-2m")

	flag.StringVar(&principalsStr, "principals", "ec2-user,ubuntu", "Valid usernames for login. Comma separated.")
	flag.StringVar(&environment, "environment", "", "The environment you want (e.g. prod).")
	flag.StringVar(&configPath, "configPath", configPath, "Path to config json.")
	flag.StringVar(&reason, "reason", "", "Reason for needing SSH certificate.")
	flag.DurationVar(&validAfterDur, "valid-after", validAfterDur, "Relative time")
	flag.DurationVar(&validBeforeDur, "valid-before", validBeforeDur, "Relative time")
	printVersion := flag.Bool("version", false, "Print the version and exit")
	flag.Parse()

	if *printVersion {
		fmt.Printf("sign_cert v.%s\n", ssh_ca_util.BuildVersion)
		os.Exit(0)
	}

	config := make(map[string]ssh_ca_util.RequesterConfig)
	err := ssh_ca_util.LoadConfig(configPath, &config)
	if err != nil {
		fmt.Println("Load Config failed:", err)
		os.Exit(1)
	}

	if reason == "" {
		fmt.Println("Must give a reason for requesting this certificate.")
		os.Exit(1)
	}
	if len(config) > 1 && environment == "" {
		fmt.Println("You must tell me which environment to use.", len(config))
		os.Exit(1)
	}
	if len(config) == 1 && environment == "" {
		for environment = range config {
			// lame way of extracting first and only key from a map?
		}
	}

	_, ok := config[environment]
	if !ok {
		fmt.Printf("Environment '%s' not found in config file.", environment)
		os.Exit(1)
	}

	caRequest := ssh_ca_client.MakeRequest()
	caRequest.SetConfig(config[environment])
	failed := trueOnError(caRequest.SetEnvironment(environment))
	failed |= trueOnError(caRequest.SetReason(reason))
	failed |= trueOnError(caRequest.SetValidAfter(validAfterDur))
	failed |= trueOnError(caRequest.SetValidBefore(validBeforeDur))
	failed |= trueOnError(caRequest.SetPrincipalsFromString(principalsStr))

	if failed == 1 {
		fmt.Println("One or more errors found. Aborting request.")
		os.Exit(1)
	}

	pubKeyContents, err := ioutil.ReadFile(config[environment].PublicKeyPath)
	if err != nil {
		fmt.Println("Trouble opening your public key file", config[environment].PublicKeyPath, err)
		os.Exit(1)
	}
	pubKey, pubKeyComment, _, _, err := ssh.ParseAuthorizedKey(pubKeyContents)
	if err != nil {
		fmt.Println("Trouble parsing your public key", err)
		os.Exit(1)
	}
	chosenKeyFingerprint := ssh_ca_util.MakeFingerprint(pubKey.Marshal())

	conn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		fmt.Println("Dial failed:", err)
		os.Exit(1)
	}
	sshAgent := agent.NewClient(conn)

	signers, err := sshAgent.Signers()
	var signer ssh.Signer
	signer = nil
	if err != nil {
		fmt.Println("No keys found in agent, can't sign request, bailing.")
		fmt.Println("ssh-add the private half of the key you want to use.")
		os.Exit(1)
	} else {
		for i := range signers {
			signerFingerprint := ssh_ca_util.MakeFingerprint(signers[i].PublicKey().Marshal())
			if signerFingerprint == chosenKeyFingerprint {
				signer = signers[i]
				break
			}
		}
	}
	if signer == nil {
		fmt.Println("ssh-add the private half of the key you want to use.")
		os.Exit(1)
	}
	caRequest.SetPublicKey(signer.PublicKey(), pubKeyComment)
	newCert, err := caRequest.EncodeAsCertificate()
	if err != nil {
		fmt.Println("Error encoding certificate request:", err)
		os.Exit(1)
	}
	err = newCert.SignCert(rand.Reader, signer)
	if err != nil {
		fmt.Println("Error signing:", err)
		os.Exit(1)
	}

	certRequest := newCert.Marshal()
	requestParameters := caRequest.BuildWebRequest(certRequest)
	requestID, err := caRequest.DoWebRequest(requestParameters)
	if err == nil {
		fmt.Printf("Cert request id: %s\n", requestID)
	} else {
		fmt.Println(err)
	}

}
