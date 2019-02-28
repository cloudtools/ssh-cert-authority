package signer

import (
	"cloud.google.com/go/kms/apiv1"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/ssh"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	"io"
	"strings"
	"time"
)

// Singleton client
var kmsClient *kms.KeyManagementClient

type GcpKmsSigner struct {
	keyUrl    string
	kmsClient *kms.KeyManagementClient
	kmsPubKey crypto.PublicKey
}

func NewSshGcpKmsSigner(keyUrl string) (ssh.Signer, error) {
	kmsSigner, err := NewGcpKmsSigner(keyUrl)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromSigner(kmsSigner)
}

func NewGcpKmsSigner(keyUrl string) (*GcpKmsSigner, error) {
	keyUrl = strings.TrimPrefix(keyUrl, "/")
	kmsClient, err := getKmsClient()
	if err != nil {
		return nil, fmt.Errorf("Unable to initialize kms client: %s", err)
	}
	ctx := context.Background()
	ctx, _ = context.WithTimeout(ctx, 10*time.Second)
	getPubKeyReq := &kmspb.GetPublicKeyRequest{
		Name: keyUrl,
	}
	kmsPubKeypb, err := kmsClient.GetPublicKey(ctx, getPubKeyReq)
	if err != nil {
		return nil, fmt.Errorf("Unable to get signing public key from kms: %s", err)
	}
	block, _ := pem.Decode([]byte(kmsPubKeypb.Pem))
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse kms public key: %s", err)
	}

	kmsSigner := &GcpKmsSigner{
		keyUrl:    keyUrl,
		kmsClient: kmsClient,
		kmsPubKey: pubKey,
	}
	return kmsSigner, nil
}

// Public returns an associated PublicKey instance.
func (g GcpKmsSigner) Public() crypto.PublicKey {
	return g.kmsPubKey
}

func (g GcpKmsSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	ctx := context.Background()
	ctx, _ = context.WithTimeout(ctx, 10*time.Second)

	req := &kmspb.AsymmetricSignRequest{
		Name: g.keyUrl,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: digest,
			},
		},
	}
	resp, err := g.kmsClient.AsymmetricSign(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("Unable to sign: %s", err)
	}
	return resp.GetSignature(), nil
}

func getKmsClient() (*kms.KeyManagementClient, error) {
	if kmsClient != nil {
		return kmsClient, nil
	}
	ctx := context.Background()
	c, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, err
	}
	return c, nil
}
