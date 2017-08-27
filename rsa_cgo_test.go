package rsa_cgo

import (
	"fmt"
	"testing"

	rsa_go "github.com/Bulesxz/rsa_cgo/go"
)

func TestCgoRsa(t *testing.T) {

	pri := CgoLoadPrivateKey("./rsa_private_key.pem")

	ori := "aaa"

	sign := CgoRsaSign(pri, ori)
	fmt.Println(sign)

	CgoDestoryKey(pri)

	pub := CgoLoadPublicKey("./rsa_public_key.pem")
	ok := CRsaVerify(pub, ori, sign)
	CgoDestoryKey(pub)
	fmt.Println(ok)
}

func TestGoRsa(t *testing.T) {
	pri, _ := rsa_go.LoadPrivateKey("./rsa_private_key.pem")
	ori := "aaa"
	sign, _ := rsa_go.Sign(pri, []byte(ori))
	fmt.Println(sign)

	//sign = "aaa"
	pub, _ := rsa_go.LoadPublicKey("./rsa_public_key.pem")
	err := rsa_go.Verify(pub, []byte(ori), sign)
	fmt.Println(err)
}

func BenchmarkGoRsa(b *testing.B) {
	pri, _ := rsa_go.LoadPrivateKey("./rsa_private_key.pem")
	pub, _ := rsa_go.LoadPublicKey("./rsa_public_key.pem")

	for i := 0; i < b.N; i++ {
		ori := "aaa"
		sign, _ := rsa_go.Sign(pri, []byte(ori))
		rsa_go.Verify(pub, []byte(ori), sign)
	}
}

func BenchmarkCgoRsa(b *testing.B) {
	pri := CgoLoadPrivateKey("./rsa_private_key.pem")
	pub := CgoLoadPublicKey("./rsa_public_key.pem")

	for i := 0; i < b.N; i++ {
		ori := "aaa"
		sign := CgoRsaSign(pri, ori)
		CRsaVerify(pub, ori, sign)
	}
}
