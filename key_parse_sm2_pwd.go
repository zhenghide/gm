package main

import (
	"crypto/sm2"
	"crypto/x509"
	"fmt"
)

func main() {
	sm2PriKey, err := sm2.GenerateKey()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("-----------------SM2私钥-----------------")
	fmt.Println(sm2PriKey)

	pwd := []byte("123456")
	priKeyStream, _ := x509.MarshalSm2EcryptedPrivateKey(sm2PriKey, pwd)
	fmt.Println("priKeyStream:", priKeyStream)
	fmt.Println("length:", len(priKeyStream))

	priKey, err := x509.ParseSm2EcryptedPrivateKey(priKeyStream, pwd)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("-----------------解析出的私钥-----------------")
	fmt.Println(priKey)

}