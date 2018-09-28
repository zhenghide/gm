package util

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

func ParseCertificateRequest(pkcs10 string) (*x509.CertificateRequest, error) {
	//解码base64证书请求
	pkcs10Byte, err := base64.StdEncoding.DecodeString(pkcs10)
	if err != nil {
		return nil, fmt.Errorf("decode pkcs10 failed: %s", err.Error())
	}
	certReq, err := x509.ParseCertificateRequest(pkcs10Byte)
	if err != nil {
		return nil, fmt.Errorf("ParseCertificateRequest failed: %s", err.Error())
	}
	return certReq, nil
}
