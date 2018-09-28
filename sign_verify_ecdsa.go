package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
)

func main()  {

	//读取私钥内容
	keyBytes, err := ioutil.ReadFile("static/ecdsa.key")
	if err != nil {
		fmt.Println("read file error")
		return
	}
	fmt.Println("-----------------SM2私钥-----------------")
	fmt.Println(string(keyBytes))

	src := "试一试"
	r, s, err := EcdsaSign(src, keyBytes, crypto.SHA256)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("-----------------R--S-----------------")
	fmt.Println(r)
	fmt.Println(s)

	//读取证书内容
	certBytes, err := ioutil.ReadFile("static/ecdsa.crt")
	if err != nil {
		fmt.Println("read file error")
		return
	}

	result, err := EcdsaVerifySign(r, s, src, string(certBytes), crypto.SHA256)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
	fmt.Println(result)

}

func EcdsaSign(origData string, privateKeyPem []byte, hash crypto.Hash) (r, s *big.Int, err error) {
	//解析成ecdsa私钥
	block, _ := pem.Decode(privateKeyPem)
	prikey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("ParseECPrivateKey fail: %s", err.Error())
	}

	h := hash.New()
	h.Write([]byte(origData))
	digest := h.Sum(nil)

	r, s, err = ecdsa.Sign(rand.Reader, prikey, digest)
	if err != nil {
		return nil, nil, fmt.Errorf("ecdsa sign fail: %s", err.Error())
	}

	return
}

func EcdsaVerifySign(r, s *big.Int, data string, pemCert string, hash crypto.Hash) (bool, error) {
	block, _ := pem.Decode([]byte(pemCert))
	if block == nil {
		return false, fmt.Errorf("failed to decode pem cert")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("ParseCertificate failed: %s", err.Error())
	}

	h := hash.New()
	h.Write([]byte(data))
	digest := h.Sum(nil)

	ecdsaPubKey, _ := cert.PublicKey.(*ecdsa.PublicKey)
	result := ecdsa.Verify(ecdsaPubKey, digest, r, s)

	return result, nil
}
