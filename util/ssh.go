package ssh_ca_util

import (
	"crypto"
	"fmt"
	"github.com/cloudtools/ssh-cert-authority/signer"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"io"
	"net/url"
	"regexp"
)

var md5Fingerprint = regexp.MustCompile("([0-9a-fA-F]{2}:){15}[0-9a-fA-F]{2}")

//This interface provides a way to reach the exported, but not accessible SignWithOpts() method
//in x/crypto/ssh/agent. Access to this is needed to sign with more secure signing algorithms
type agentKeyringSigner interface {
	SignWithOpts(rand io.Reader, data []byte, opts crypto.SignerOpts) (*ssh.Signature, error)
}

//A struct to wrap an SSH Signer with one that will switch to SHA256 Signatures.
//Replaces the call to Sign() with a call to SignWithOpts using HashFunc() algorithm.
type Sha256Signer struct {
	ssh.Signer
}

func (s Sha256Signer) HashFunc() crypto.Hash {
	return crypto.SHA256
}

func (s Sha256Signer) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	if aks, ok := s.Signer.(agentKeyringSigner); !ok {
		return nil, fmt.Errorf("ssh: can't wrap a non ssh agentKeyringSigner")
	} else {
		return aks.SignWithOpts(rand, data, s)
	}
}

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
			return Sha256Signer{signers[i]}, nil
		}
	}
	return nil, fmt.Errorf("Unable to find your SSH key (%s) in agent. Consider ssh-add", fingerprint)
}
