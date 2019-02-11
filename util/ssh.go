package ssh_ca_util

import (
	"fmt"
	"github.com/cloudtools/ssh-cert-authority/signer"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"io"
	"net/url"
	"regexp"
)

var md5Fingerprint = regexp.MustCompile("([0-9a-fA-F]{2}:){15}[0-9a-fA-F]{2}")

func GetSignerForFingerprintOrUrl(fingerprint string, conn io.ReadWriter) (ssh.Signer, error) {
	isFingerprint := md5Fingerprint.MatchString(fingerprint)
	if isFingerprint {
		return GetSignerForFingerprint(fingerprint, conn)
	}
	keyUrl, err := url.Parse(fingerprint)
	if err != nil {
		return nil, fmt.Errorf("Ignoring invalid private key url: '%s'. Error parsing: %s", fingerprint, err)
	}
	if keyUrl.Scheme != "gcpkms" {
		return nil, fmt.Errorf("gcpkms:// is the only supported url scheme")
	}
	return getSignerForGcpKms(keyUrl.Path)
}
func getSignerForGcpKms(keyUrl string) (ssh.Signer, error) {
	return signer.NewSshGcpKmsSigner(keyUrl)
}

func GetSignerForFingerprint(fingerprint string, conn io.ReadWriter) (ssh.Signer, error) {
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
