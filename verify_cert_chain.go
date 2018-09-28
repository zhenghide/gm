package main

import (
	"fmt"
	"io/ioutil"

	"crypto/x509"
	"encoding/pem"
	"strings"
	"time"
)

func main() {
	//读取证书内容
	orgCertBytes, err := ioutil.ReadFile("static/Admin@org1.example.com-cert.pem")
	if err!= nil{
		fmt.Println(err)
	}

	caCertBytes, err := ioutil.ReadFile("static/ca.org1.example.com-cert.pem")
	if err!= nil{
		fmt.Println(err)
	}
	//验证证书链
	chain := GetCertsFromChain(string(caCertBytes))
	err = VerifyCert(string(orgCertBytes), chain)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}else {
		fmt.Println("ok")
	}
}

//
func GetCertsFromChain(chain string) []string {
	var r []string
	s := "-----BEGIN"
	l := len(s)
	index1 := strings.Index(chain, s)
	for {
		if index1 != -1 {
			index2 := strings.Index(chain[index1+l:], s)
			if index2 != -1 {
				r = append(r, chain[index1:index1+l+index2])
			} else {
				r = append(r, chain[index1:])
				break
			}
			index1 = index1 + l + index2
		} else {
			break
		}
	}

	return r
}

//升级版验证证书链方法
func VerifyCert(cert string, certChain []string) error {
	//解码pem证书
	certDERBlock, _ := pem.Decode([]byte(cert))
	if certDERBlock == nil {
		return fmt.Errorf("decode pem cert failed")
	}
	c, err := x509.ParseCertificate(certDERBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse x509 cert fail: %s", err.Error())
	}

	var cas []*x509.Certificate
	for _, caCert := range certChain {
		certDERBlock, _ := pem.Decode([]byte(caCert))
		if certDERBlock == nil {
			return fmt.Errorf("decode pem cacert failed")
		}
		ca, err := x509.ParseCertificate(certDERBlock.Bytes)
		if err != nil {
			return fmt.Errorf("parse x509 cacert fail: %s", err.Error())
		}

		cas = append(cas, ca)
	}

	return VerifyX509Cert(c, cas)
}

func VerifyX509Cert(c *x509.Certificate, cas []*x509.Certificate) error {
	now := time.Now()
	if now.Before(c.NotBefore) || now.After(c.NotAfter) {
		return fmt.Errorf("certificate has expired or is not yet valid")
	}

	var err error
	for _, ca := range cas {
		err = c.CheckSignatureFrom(ca)
		fmt.Println("c:", err)
		if err == nil {
			err = ca.CheckSignatureFrom(ca)
			fmt.Println("ca:", err)
			if err == nil { //root ca
				return nil
			} else {
				return VerifyX509Cert(ca, cas)
			}
		}
	}
	return err
}
