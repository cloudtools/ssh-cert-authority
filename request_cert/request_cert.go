package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/cloudtools/ssh-cert-authority/util"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const buildVersion string = "dev"

func main() {
	var principalsStr, environment, reason string
	var validBeforeDur, validAfterDur time.Duration
	commandLineHasErrors := false

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
		fmt.Printf("sign_cert v.%s\n", buildVersion)
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

	timeNow := time.Now().Unix()
	validAfter := uint64(timeNow + int64(validAfterDur.Seconds()))
	validBefore := uint64(timeNow + int64(validBeforeDur.Seconds()))

	if validAfter >= validBefore {
		fmt.Printf("valid-after (%v) >= valid-before (%v). Which does not make sense.\n",
			time.Unix(int64(validAfter), 0), time.Unix(int64(validBefore), 0))
		commandLineHasErrors = true
	}

	principals := strings.Split(strings.TrimSpace(principalsStr), ",")
	if principalsStr == "" {
		fmt.Println("You didn't specify any principals. This cert is worthless.")
		commandLineHasErrors = true
	}

	if commandLineHasErrors {
		fmt.Println("One or more command line flags are busted.")
		os.Exit(1)
	}

	pubKeyFile, err := os.Open(config[environment].PublicKeyPath)
	if err != nil {
		fmt.Println("Trouble opening your public key file", pubKeyFile, err)
		os.Exit(1)
	}
	buf := make([]byte, 1<<13)
	count, err := pubKeyFile.Read(buf)
	if err != nil || count == 0 {
		fmt.Println("Trouble opening your public key file", pubKeyFile, err)
		os.Exit(1)
	}
	pubKey, pubKeyComment, _, _, err := ssh.ParseAuthorizedKey(buf)
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

	var newCert ssh.Certificate
	newCert.Nonce = make([]byte, 32)
	newCert.Key = signer.PublicKey()
	newCert.Serial = 0
	newCert.CertType = ssh.UserCert
	newCert.KeyId = pubKeyComment
	newCert.ValidPrincipals = principals
	newCert.ValidAfter = validAfter
	newCert.ValidBefore = validBefore
	newCert.Extensions = make(map[string]string)
	newCert.Extensions["permit-agent-forwarding"] = ""
	newCert.Extensions["permit-port-forwarding"] = ""
	newCert.Extensions["permit-pty"] = ""

	err = newCert.SignCert(rand.Reader, signer)
	if err != nil {
		fmt.Println("Error signing:", err)
		os.Exit(1)
	}

	certRequest := newCert.Marshal()
	requestParameters := make(url.Values)
	requestParameters["cert"] = make([]string, 1)
	requestParameters["cert"][0] = base64.StdEncoding.EncodeToString(certRequest)
	requestParameters["environment"] = make([]string, 1)
	requestParameters["environment"][0] = environment
	requestParameters["reason"] = make([]string, 1)
	requestParameters["reason"][0] = reason
	resp, err := http.PostForm(config[environment].SignerUrl+"cert/requests", requestParameters)
	if err != nil {
		fmt.Println("Error sending request to signer daemon:", err)
		os.Exit(1)
	}
	respBuf, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		fmt.Println("Error retrieving response to our request. Try again?", err)
		os.Exit(1)
	}
	if resp.StatusCode == 201 {
		fmt.Printf("Cert request id: %s\n", string(respBuf))
	} else {
		fmt.Printf("Cert request rejected: %s\n", string(respBuf))
		os.Exit(1)
	}

}
