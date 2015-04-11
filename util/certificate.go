package ssh_ca_util

import (
	"crypto"
	"fmt"
	"golang.org/x/crypto/ssh"
	"strings"
	"time"
)

func PrintForInspection(cert ssh.Certificate) {
	fmt.Println("Certificate data:")
	fmt.Printf("  Serial: %v\n", cert.Serial)
	fmt.Printf("  Key id: %v\n", cert.KeyId)
	fmt.Printf("  Principals: %v\n", cert.ValidPrincipals)
	fmt.Printf("  Options: %v\n", cert.Permissions.CriticalOptions)
	fmt.Printf("  Permissions: %v\n", cert.Permissions.Extensions)
	fmt.Printf("  Valid for public key: %s\n", MakeFingerprint(cert.Key.Marshal()))
	var colorStart, colorEnd string
	if uint64(time.Now().Unix()+3600*24) < cert.ValidBefore {
		colorStart = "\033[91m"
		colorEnd = "\033[0m"
	}
	fmt.Printf("  Valid from %v - %s%v%s\n",
		time.Unix(int64(cert.ValidAfter), 0),
		colorStart, time.Unix(int64(cert.ValidBefore), 0), colorEnd)
}

func Print(c ssh.Certificate) string {
	var output string

	output += fmt.Sprintf("Cert serial: %v\n", c.Serial)
	output += fmt.Sprintf("Cert valid for public key: %s\n", MakeFingerprint(c.Key.Marshal()))
	output += ValidityPeriodString(c)
	return output
}

func ValidityPeriodString(c ssh.Certificate) string {
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
