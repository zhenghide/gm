package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sm2"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"gm/util"
)

func main() {
	sm2PrivateKey, err := sm2.GenerateKey()
	priKeyDerStream, err := x509.MarshalPKCS8PrivateKey(sm2PrivateKey)

	fmt.Println(priKeyDerStream)
	fmt.Println("length", len(priKeyDerStream))

	//编码私钥
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: priKeyDerStream,
	}
	buffer := bytes.NewBuffer(make([]byte, 0))
	err = pem.Encode(buffer, block)
	if err != nil {
		fmt.Println(err)
	}
	pemPrikey := buffer.String()
	fmt.Println(pemPrikey)

	subject := pkix.Name{
		Country:            []string{""},
		Organization:       []string{"aisino"},
		OrganizationalUnit: []string{""},
		Locality:           []string{""},
		Province:           []string{""},
		StreetAddress:      []string{""},
		PostalCode:         []string{""},
		CommonName:         "zht",
	}

	req := &x509.CertificateRequest{
		Subject: subject,
	}

	pkcs10DerStream, err := x509.CreateCertificateRequest(rand.Reader, req, sm2PrivateKey)
	pkcs10 := base64.StdEncoding.EncodeToString(pkcs10DerStream)
	fmt.Println("---------------PKCS10BASE64---------------")
	fmt.Println(pkcs10)

	certReq, _ := util.ParseCertificateRequest(pkcs10)
	fmt.Println("SignatureAlgorithm:", certReq.SignatureAlgorithm)

}

