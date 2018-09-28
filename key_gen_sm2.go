package main

import (
	"crypto/sm2"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"gm/util"
)

func main() {
	sm2PriKey, err := sm2.GenerateKey()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("-----------------SM2私钥-----------------")
	fmt.Println(sm2PriKey)



	pemPriKey, _ := util.PriKeyToPem(sm2PriKey)
	fmt.Println(pemPriKey)

	priKeyStream, _ := x509.MarshalPKCS8PrivateKey(sm2PriKey)
	fmt.Println("priKeyStream:", priKeyStream)
	fmt.Println("length:", len(priKeyStream))

	//解析出SM2公钥
	pubKeyStream, _ := x509.MarshalSm2PublicKey(&sm2PriKey.PublicKey)
	fmt.Println("-----------------SM2公钥-----------------")
	fmt.Println(pubKeyStream)
	fmt.Println("length:", len(pubKeyStream))


	//编码SM2公钥
	tempPubKey := base64.StdEncoding.EncodeToString(pubKeyStream)
	fmt.Println("-----------------BASE64-----------------")
	fmt.Println(tempPubKey)
	
}
