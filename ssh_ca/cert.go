package ssh_ca

import (
	"crypto"
	"fmt"
	"golang.org/x/crypto/ssh"
	"strings"
	"time"
)

type SshCertificate struct {
	ssh.Certificate
}

func (c *SshCertificate) BytesForSigning() []byte {
	c.Signature = nil
	cert_bytes := c.Marshal()
	return cert_bytes[:len(cert_bytes)-4]
}

func (c *SshCertificate) GoString() string {
	var output string

	output += fmt.Sprintf("Cert serial: %v\n", c.Serial)
	output += fmt.Sprintf("Cert valid for public key: %s\n", MakeFingerprint(c.Key.Marshal()))
	output += c.ValidityPeriodString()
	return output
}

func (c *SshCertificate) ValidityPeriodString() string {
	return fmt.Sprintf("Valid between %v and %v\n",
		time.Unix(int64(c.ValidAfter), 0), time.Unix(int64(c.ValidBefore), 0))
}

func MakeFingerprint(key_blob []byte) string {
	hasher := crypto.MD5.New()
	hasher.Write(key_blob)
	hash_bytes := hasher.Sum(nil)
	retval := make([]string, hasher.Size(), hasher.Size())
	for i := range hash_bytes {
		retval[i] = fmt.Sprintf("%02x", hash_bytes[i])
	}
	return strings.Join(retval, ":")
}
