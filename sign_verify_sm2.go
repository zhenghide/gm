package main

import (
	"crypto/sm2"
	"crypto/sm3"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
)

func main() {
	//读取私钥内容
	keyBytes, err := ioutil.ReadFile("static/yang.key")
	if err != nil {
		fmt.Println("read file error")
		return
	}
	fmt.Println("-----------------SM2私钥-----------------")
	fmt.Println(string(keyBytes))

	src := "试一试"
	r, s, err := SM2Sign(src, keyBytes)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("-----------------R--S-----------------")
	fmt.Println(r)
	fmt.Println(s)

	//读取证书内容
	certBytes, err := ioutil.ReadFile("static/yang.crt")
	if err != nil {
		fmt.Println("read file error")
		return
	}

	result, err := SM2VerifySign(r,s,src,string(certBytes))
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
	fmt.Println(result)
}


//SM2签名
func SM2Sign(origData string, privateKeyPem []byte) (r, s *big.Int, err error) {
	//解析成sm2私钥
	block, _ := pem.Decode(privateKeyPem)
	prikey, err := x509.ParseSm2PrivateKey(block.Bytes)
	if err != nil {
		fmt.Println(err)
		return nil, nil, err
	}

	//fmt.Println("私钥类型:", reflect.TypeOf(prikey))

	h := sm3.New()
	h.Write([]byte(origData))
	digest := h.Sum(nil)

	r, s, err = sm2.Sign(prikey, digest)
	if err != nil {
		fmt.Println(err)
		return nil, nil, err
	}

	return
}

//SM2验签
func SM2VerifySign(r, s *big.Int, data string, pemCert string) (bool, error) {
	block, _ := pem.Decode([]byte(pemCert))
	if block == nil {
		fmt.Println("error")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println(err)
	}
	h := sm3.New()
	h.Write([]byte(data))
	digest := h.Sum(nil)

	sm2PubKey := cert.PublicKey.(*sm2.PublicKey)
	result := sm2.Verify(sm2PubKey, digest, r, s)
	return result, nil
}
