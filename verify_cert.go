package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"reflect"
)

func main() {
	//certPath := "/tmp/ca-test/certs/cert0-cert.pem"
	certPath := "static/hxUser.crt"
	//读取证书内容
	certBytes, err1 := ioutil.ReadFile(certPath)
	if err1 != nil {
		fmt.Println(err1)
	}

	block, _ := pem.Decode(certBytes)
	if block == nil {
		fmt.Println("block is nil")
	}

	cert, err2 := x509.ParseCertificate(block.Bytes)
	if err2 != nil {
		fmt.Println(err2)
	}

	fmt.Println("Subject:", cert.Subject)
	fmt.Println("PubKeyType:", reflect.TypeOf(cert.PublicKey))

	//caCertPath := "/tmp/ca-test/ca/root1-cert.pem"
	caCertPath := "static/hxCa.crt"
	//读取证书内容
	caCertBytes, err3 := ioutil.ReadFile(caCertPath)
	if err1 != nil {
		fmt.Println(err3)
	}

	caBlock, _ := pem.Decode(caCertBytes)
	if block == nil {
		fmt.Println("block is nil")
	}

	caCert, err4 := x509.ParseCertificate(caBlock.Bytes)
	if err4 != nil {
		fmt.Println(err4)
	}

	fmt.Println("caSubject:", caCert.Subject)
	fmt.Println("caPubKeyType:", reflect.TypeOf(caCert.PublicKey))

	err5 := cert.CheckSignatureFrom(caCert)
	if err5 != nil {
		fmt.Println(err5)
		panic(err5)
	} else {
		fmt.Println("ok")
	}

}
