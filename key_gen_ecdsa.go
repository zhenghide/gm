package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

func main() {
	ecdsaPriKey, err := ecdsa.GenerateKey(elliptic.P256(),rand.Reader)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("-----------------私钥-----------------")
	fmt.Println(ecdsaPriKey)

	priKeyStream, _ := x509.MarshalECPrivateKey(ecdsaPriKey)
	fmt.Println("-----------------priKeyStream-----------------")
	fmt.Println(priKeyStream)
	fmt.Println("length", len(priKeyStream))

	block := &pem.Block{
		Type:  "PRIVATE EC KEY",
		Bytes: priKeyStream,
	}

	priKey := bytes.NewBuffer(make([]byte, 0))
	err = pem.Encode(priKey, block)
	if err != nil {
		fmt.Println(err)
	}
	pemPriKey := priKey.String()
	fmt.Println("-----------------pemPriKey-----------------")
	fmt.Println(pemPriKey)


	//解析出公钥
	pubKeyStream, _ := x509.MarshalPKIXPublicKey(&ecdsaPriKey.PublicKey)
	fmt.Println("-----------------SM2公钥-----------------")
	fmt.Println(pubKeyStream)


	//编码公钥
	tempPubKey := base64.StdEncoding.EncodeToString(pubKeyStream)
	fmt.Println("-----------------BASE64-----------------")
	fmt.Println(tempPubKey)

	//产生证书请求
	subject := pkix.Name{
		Country:            []string{"CN"},
		Organization:       []string{"CN"},
		OrganizationalUnit: []string{"CN"},
		Locality:           []string{"CN"},
		Province:           []string{"CN"},
		StreetAddress:      []string{"CN"},
		PostalCode:         []string{"CN"},
		CommonName:         "zht",
	}
	req := &x509.CertificateRequest{
		Subject: subject,
	}

	pkcs10DerStream, err := x509.CreateCertificateRequest(rand.Reader, req, ecdsaPriKey)
	fmt.Println(pkcs10DerStream)
	
}
