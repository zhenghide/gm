package main

import (
	"fmt"
	"gm/util"
	"io/ioutil"
)

func main()  {
	//读取证书内容
	certByte, err := ioutil.ReadFile("static/sm2_new.p7b")
	if err != nil {
		fmt.Println("read file error")
		return
	}

	pemCert, err := util.P7bToPem(string(certByte))
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(pemCert)
}
