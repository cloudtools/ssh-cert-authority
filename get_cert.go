package main

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/bobveznat/ssh-ca-ss/ssh_ca"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

const buildVersion string = "dev"

func main() {
	var environment string

	home := os.Getenv("HOME")
	if home == "" {
		home = "/"
	}
	configPath := home + "/.ssh_ca/requester_config.json"

	flag.StringVar(&environment, "environment", "", "The environment you want (e.g. prod).")
	printVersion := flag.Bool("version", false, "Print the version and exit")
	flag.Parse()

	if *printVersion {
		fmt.Printf("sign_cert v.%s\n", buildVersion)
		os.Exit(0)
	}

	certRequestID := flag.Args()[0]

	allConfig, err := ssh_ca.LoadSignerConfig(configPath)
	if err != nil {
		fmt.Println("Load Config failed:", err)
		os.Exit(1)
	}

	if certRequestID == "" {
		fmt.Println("Specify --cert-request-id")
		os.Exit(1)
	}

	if len(allConfig) > 1 && environment == "" {
		fmt.Println("You must tell me which environment to use.", len(allConfig))
		os.Exit(1)
	}
	if len(allConfig) == 1 && environment == "" {
		for environment = range allConfig {
			// lame way of extracting first and only key from a map?
		}
	}
	config := allConfig[environment]

	getResp, err := http.Get(config.SignerUrl + "cert/requests/" + certRequestID)
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

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(getRespBuf)
	if err != nil {
		fmt.Println("Trouble parsing response", err)
		os.Exit(1)
	}
	cert := pubKey.(*ssh.Certificate)

	agentConn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		fmt.Println("Dial failed:", err)
		os.Exit(1)
	}
	sshAgent := agent.NewClient(agentConn)
	// We genuinely don't care if this fails, its not actionable
	sshAgent.Remove(cert.Key)
	pubKeyPath, err := findKeyLocally(cert.Key)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	pubKeyPath = strings.Replace(pubKeyPath, ".pub", "-cert.pub", 1)
	err = ioutil.WriteFile(pubKeyPath, getRespBuf, 0644)
	if err != nil {
		fmt.Printf("Couldn't write certificate file to %s: %s\n", pubKeyPath, err)
	}

	fmt.Println("Certificate data:")
	fmt.Printf("  Serial: %v\n", cert.Serial)
	fmt.Printf("  Key id: %v\n", cert.KeyId)
	fmt.Printf("  Principals: %v\n", cert.ValidPrincipals)
	fmt.Printf("  Options: %v\n", cert.Permissions.CriticalOptions)
	fmt.Printf("  Permissions: %v\n", cert.Permissions.Extensions)
	fmt.Printf("  Valid for public key: %s\n", ssh_ca.MakeFingerprint(cert.Key.Marshal()))
	var colorStart, colorEnd string
	if uint64(time.Now().Unix()+3600*24) < cert.ValidBefore {
		colorStart = "\033[91m"
		colorEnd = "\033[0m"
	}
	fmt.Printf("  Valid from %v - %s%v%s\n",
		time.Unix(int64(cert.ValidAfter), 0),
		colorStart, time.Unix(int64(cert.ValidBefore), 0), colorEnd)

	privKeyPath := strings.Replace(pubKeyPath, "-cert.pub", "", 1)
	secondsRemaining := cert.ValidBefore - uint64(time.Now().Unix())
	cmd := exec.Command("ssh-add", "-t", fmt.Sprintf("%d", secondsRemaining), privKeyPath)
	var out bytes.Buffer
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	err = cmd.Run()
	if err != nil {
		fmt.Printf("Error in ssh-add: %v", out.String())
		os.Exit(1)
	}
}

func findKeyLocally(key ssh.PublicKey) (string, error) {
	sshDir := os.Getenv("HOME") + "/.ssh"
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
				return "", fmt.Errorf("Trouble reading public key %s: %s\n", pubKeyPath, err)
			}
			pubKey, _, _, _, err := ssh.ParseAuthorizedKey(pubBuf)
			if err != nil {
				return "", fmt.Errorf("Trouble parsing public key %s: %s\n", pubKeyPath, err)
			}
			if bytes.Equal(pubKey.Marshal(), key.Marshal()) {
				return pubKeyPath, nil
			}
		}
	}
	return "", fmt.Errorf("Couldn't find ssh key for cert.\n")
}
