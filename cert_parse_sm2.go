package main

import (
	"fmt"
	"gm/util"
	"io/ioutil"
	"reflect"
)

func main() {
	//读取证书内容
	certBytes, err := ioutil.ReadFile("static/sm2Ca.crt")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("-----------------读取的内容-----------------")
	fmt.Println(string(certBytes))

	cert, err := util.PemCert2Cert(string(certBytes))
	fmt.Println("cert:", cert)

	//subject := cert.Subject
	//fmt.Println("Subject-----", subject)

	pubKey := cert.PublicKey
	fmt.Println("PublicKey-----", pubKey)
	fmt.Println("PublicKey Type-----", reflect.TypeOf(pubKey))
	fmt.Println("SignatureAlgorithm", cert.SignatureAlgorithm)

}





