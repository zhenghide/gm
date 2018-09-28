package main

import (
	"bytes"
	"crypto/sm2"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
)

func main()  {
	//读取内容
	keyBytes, err := ioutil.ReadFile("static/tmpp.key")
	if err != nil {
		fmt.Println(err)
	}

	//解码私钥
	oldBlock, _ := pem.Decode(keyBytes)
	if oldBlock == nil {
		fmt.Println("oldBlock is nil")
	}

	fmt.Println("---------------PriKey Bytes---------------")
	fmt.Println(oldBlock.Bytes)
	fmt.Println("length:", len(oldBlock.Bytes))

	fmt.Println("---------------keyPri32---------------")
	keyPri32 := oldBlock.Bytes[7:39]
	fmt.Println(keyPri32)

	//keyPri32 := []byte{7,218,187,199,96,246,42,157,39,251,94,105,64,146,105,65,172,218,132,149,189,164,18,184,139,129,7,89,122,77,176,90}
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
