package ssh_ca_client

import (
	"golang.org/x/crypto/ssh"
	"testing"
	"time"
)

const samplePublicKeyString string = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCqwK8IchsTOuW3snG3MuZHjINw8YNR4T0+jlSgjH/d93bN2fuABVvlxRiAjSNNWTmuln8Jyto5PFP4/FqDgjhra3qIb6luf1XPmlnHH23/o56RS3boNDsaXAPIPhghwODjPZX2dau5jAC2y0zvcSJv0nXrpDthdHiUjYLjHKcSSpSoTAXHV2yOYe+hQ6rA+ZwVevXQrkR1mexlm0eOdNxC4AsTp7kE5E4IN6Pa4w2K5axNa9cZ1MSh9afySpmc1dinbrUmqBFtOLh8tarPsuDcTGso9jWGH/06ENkU8jTP7YKf7J0YlSsye/iuVEASYz8w1M6PlK5D06VYp0P6flgP a-testing-key"

func TestMakeRequest(t *testing.T) {
	req := MakeCertRequest()
	if req.environment != "" && req.reason != "" {
		t.Errorf("Failed the very basic task of making an empty request")
	}
}

func TestEmptyIsInvalid(t *testing.T) {
	req := MakeCertRequest()
	err := req.Validate()
	if err == nil {
		t.Errorf("An empty request was somehow valid.")
	}
}

func TestValid(t *testing.T) {
	req := MakeCertRequest()
	req.SetEnvironment("testing")
	req.SetReason("this is a test of the emergency broadcast system")
	dur, _ := time.ParseDuration("+2d")
	req.SetValidBefore(dur)
	dur, _ = time.ParseDuration("-2m")
	req.SetValidAfter(dur)
	req.SetPrincipalsFromString("ubuntu")
	pubKey, comment, _, _, _ := ssh.ParseAuthorizedKey([]byte(samplePublicKeyString))
	req.SetPublicKey(pubKey, comment)
	err := req.Validate()
	if err != nil {
		t.Fatalf("Cert that should have been valid didn't validate: %v", err)
	}
	cert, err := req.EncodeAsCertificate()
	if err != nil {
		t.Fatalf("Unable to make a certificate: %v", err)
	}

	if cert.Key != req.publicKey {
		t.Fatalf("Public key not set correctly.")
	}
	if cert.Serial != 0 {
		t.Fatalf("Serial not valid.")
	}
	if cert.CertType != ssh.UserCert {
		t.Fatalf("Cert isn't a user cert?.")
	}
	if cert.KeyId != req.keyID {
		t.Fatalf("key ids don't match")
	}
	// Use len of slice as a proxy for equality of slice
	if len(cert.ValidPrincipals) != len(req.principals) {
		t.Fatalf("principals mismatch")
	}
	if cert.ValidAfter != req.validAfter {
		t.Fatalf("valid after mismatch")
	}
	if cert.ValidBefore != req.validBefore {
		t.Fatalf("valid before mismatch")
	}
}
