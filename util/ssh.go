package ssh_ca_util

import (
	"fmt"
	"github.com/cloudtools/ssh-cert-authority/signer"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"io"
	"net/url"
)

func GetSignerForFingerprint(fingerprint string, conn io.ReadWriter) (ssh.Signer, error) {
	keyUrl, err := url.Parse(fingerprint)
	if err != nil {
		return nil, fmt.Errorf("Ignoring invalid private key url: '%s'. Error parsing: %s", fingerprint, err)
	}
	if keyUrl.Scheme == "gcpkms" {
		return getSignerForGcpKms(keyUrl.Path)
	} else {
		return getSignerForSshAgent(fingerprint, conn)
	}
}
func getSignerForGcpKms(keyUrl string) (ssh.Signer, error) {
	return signer.NewSshGcpKmsSigner(keyUrl)
}

func getSignerForSshAgent(fingerprint string, conn io.ReadWriter) (ssh.Signer, error) {
	sshAgent := agent.NewClient(conn)
	signers, err := sshAgent.Signers()
	if err != nil {
		return nil, fmt.Errorf("Unable to find your SSH key (%s) in agent. Consider ssh-add", fingerprint)
	}
	for i := range signers {
		signerFingerprint := MakeFingerprint(signers[i].PublicKey().Marshal())
		if signerFingerprint == fingerprint {
			return signers[i], nil
		}
	}
	return nil, fmt.Errorf("Unable to find your SSH key (%s) in agent. Consider ssh-add", fingerprint)
}
