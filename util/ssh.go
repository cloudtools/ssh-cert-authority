package ssh_ca_util

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"io"
)

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
