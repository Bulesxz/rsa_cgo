package rsa_go

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func Sign(priKey *rsa.PrivateKey, data []byte) (string, error) {
	hash := crypto.SHA1
	h := hash.New()
	h.Write(data)
	hashed := h.Sum(nil)

	bs, err := rsa.SignPKCS1v15(rand.Reader, priKey, hash, hashed)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(bs), nil
}

func Verify(pubKey *rsa.PublicKey, data []byte, sig string) error {
	bs, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return err
	}

	hash := crypto.SHA1
	h := hash.New()
	h.Write(data)
	hashed := h.Sum(nil)

	return rsa.VerifyPKCS1v15(pubKey, hash, hashed, bs)
}

func LoadPublicKey(publicKeyPath string) (*rsa.PublicKey, error) {
	certPEMBlock, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		return nil, err
	}

	return ParsePublicKey(certPEMBlock)
}

func LoadPrivateKey(prikeyPath string) (*rsa.PrivateKey, error) {
	certPEMBlock, err := ioutil.ReadFile(prikeyPath)
	if err != nil {
		return nil, err
	}

	return ParsePrivateKey(certPEMBlock)
}

func ParsePrivateKey(data []byte) (*rsa.PrivateKey, error) {
	pemData, err := pemParse(data, "RSA PRIVATE KEY")
	if err != nil {
		return nil, err
	}

	return x509.ParsePKCS1PrivateKey(pemData)
}

func ParsePublicKey(data []byte) (*rsa.PublicKey, error) {
	pemData, err := pemParse(data, "PUBLIC KEY")
	if err != nil {
		return nil, err
	}

	keyInterface, err := x509.ParsePKIXPublicKey(pemData)
	if err != nil {
		return nil, err
	}

	pubKey, ok := keyInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Could not cast parsed key to *rsa.PublickKey")
	}

	return pubKey, nil
}

func pemParse(data []byte, pemType string) ([]byte, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("No PEM block found")
	}
	if pemType != "" && block.Type != pemType {
		return nil, fmt.Errorf("Key's type is '%s', expected '%s'", block.Type, pemType)
	}
	return block.Bytes, nil
}
