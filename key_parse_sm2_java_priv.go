package main

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"reflect"
)

func main() {
	//读取内容
	keyBytes, err := ioutil.ReadFile("static/1-1.key")
	if err != nil {
		fmt.Println(err)
	}

	//解码私钥
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		fmt.Println("block is nil")
	}
	fmt.Println(block.Bytes)
	fmt.Println("length:", len(block.Bytes))

	privateKey, err := x509.ParseSm2PrivateKey(block.Bytes)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("-----privateKey-----")
	fmt.Println(privateKey)
	fmt.Println("type:", reflect.TypeOf(privateKey))

	stream, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	fmt.Println(stream)
	fmt.Println("length:", len(stream))

	fmt.Println("-----------------16进制-----------------")
	fmt.Printf("%0x", stream)
	fmt.Println("")

	if err != nil {
		fmt.Println(err)
	}

	pubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: stream,
	}
	pubKey := bytes.NewBuffer(make([]byte, 0))
	err = pem.Encode(pubKey, pubBlock)
	if err != nil {
		fmt.Println(err)
	}

	pemKey := pubKey.String()
	fmt.Println(pemKey)

	//sm2PubKey, err := x509.ParsePKIXPublicKey(stream)
	//fmt.Println("-----sm2PubKey-----")
	//fmt.Println(sm2PubKey)
	//fmt.Println("KEYTYPE:", reflect.TypeOf(sm2PubKey))

}

func fromHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}
