package main

import (
	"crypto/x509"
	"fmt"
)

func main() {

	pubB := []byte{48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 129, 28, 207, 85, 1, 130, 45, 3, 66, 0, 4, 233, 114, 166, 49, 76, 93, 192, 127, 172, 110, 4, 122, 99, 20, 48, 45, 11, 46, 233, 77, 11, 54, 86, 19, 235, 137, 78, 117, 34, 23, 193, 45, 178, 83, 160, 44, 110, 166, 53, 216, 224, 80, 122, 184, 111, 82, 26, 110, 117, 253, 90, 129, 89, 9, 46, 19, 125, 189, 114, 43, 163, 25, 113, 54}
	pubKey, err := x509.ParsePKIXPublicKey(pubB)

	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(pubKey)

	////读取内容
	//keyBytes, err := ioutil.ReadFile("static/33.key")
	//if err != nil {
	//	fmt.Println(err)
	//}
	//
	////解码私钥
	//block, _ := pem.Decode(keyBytes)
	//if block == nil {
	//	fmt.Println("block is nil")
	//}
	//fmt.Println(block.Bytes)
	//fmt.Println("length:", len(block.Bytes))
	//
	//sm2PubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	//fmt.Println("-----sm2PubKey-----")
	//fmt.Println(sm2PubKey)
	//fmt.Println("KEYTYPE:", reflect.TypeOf(sm2PubKey))

}
