package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"reflect"
)

func main() {

	//读取内容
	keyBytes, err := ioutil.ReadFile("static/rsa.key")
	if err != nil {
		fmt.Println(err)
	}

	//解码私钥
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		fmt.Println("block is nil")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("privateKey-----", privateKey)
	fmt.Println("typr-----", reflect.TypeOf(privateKey))

	stream,err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	fmt.Println(stream)
	fmt.Println("length:", len(stream))

	fmt.Println("-----------------16进制-----------------")
	fmt.Printf("%0x", stream)
	fmt.Println("")

	rsaPubKey, err := x509.ParsePKIXPublicKey(stream)
	fmt.Println("-----rsaPubKey-----")
	fmt.Println(rsaPubKey)
	fmt.Println("KEYTYPE:", reflect.TypeOf(rsaPubKey))

}