package main

import (
	"strings"
	"testing"
)

func TestRsaGeneration(t *testing.T) {
	rsaKey, err := generateRsa()
	if err != nil {
		t.Errorf("failed to generate rsa key: %s", err)
	}
	if !strings.Contains(string(rsaKey), "RSA PRIVATE KEY") {
		t.Errorf("Didn't generate an RSA key?: %s", rsaKey)
	}
}

func TestEcdsaGeneration(t *testing.T) {
	ecdsaKey, err := generateEcdsa()
	if err != nil {
		t.Errorf("failed to generate ecdsa key: %s", err)
	}
	if !strings.Contains(string(ecdsaKey), "EC PRIVATE KEY") {
		t.Errorf("Didn't generate an ECDSA key?: %s", ecdsaKey)
	}
}
