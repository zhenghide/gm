package main

import (
	"bytes"
	"crypto/sm2"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
)

func main() {
	////读取内容
	//keyBytes, err := ioutil.ReadFile("static/tmpp.key")
	//if err != nil {
	//	fmt.Println(err)
	//}
	//
	////解码私钥
	//oldBlock, _ := pem.Decode(keyBytes)
	//if oldBlock == nil {
	//	fmt.Println("oldBlock is nil")
	//}
	//
	//fmt.Println("---------------PriKey Bytes---------------")
	//fmt.Println(oldBlock.Bytes)
	//fmt.Println("length:", len(oldBlock.Bytes))
	//
	//fmt.Println("---------------keyPri32---------------")
	//keyPri32 := oldBlock.Bytes[7:39]
	//fmt.Println(keyPri32)

	keyPri32 := []byte{183, 31, 95, 193, 135, 127, 167, 93, 50, 143, 120, 97, 136, 217, 106, 168, 32, 166, 19, 253, 186, 53, 132, 16, 23, 121, 66, 250, 185, 36, 203, 38}
	d := new(big.Int).SetBytes(keyPri32)
	c := sm2.P256Sm2()
	priv := new(sm2.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = d
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(d.Bytes())

	prikeyBytes, err := x509.MarshalSm2PrivateKey(priv)
	if err != nil {
		fmt.Println(err)
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: prikeyBytes,
	}
	priKey := bytes.NewBuffer(make([]byte, 0))
	err = pem.Encode(priKey, block)
	if err != nil {
		fmt.Println(err)
	}

	pemKey := priKey.String()
	fmt.Println(pemKey)
}
