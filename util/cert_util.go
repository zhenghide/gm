package util

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

func PemCert2Cert(pemCert string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemCert))
	if block == nil {
		return nil, errors.New("failed to decode pem cert")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func GetCertSn(pemCert string) (sn string, err error) {
	//解析pem证书
	cert, err := PemCert2Cert(pemCert)
	if err != nil {
		return "", fmt.Errorf("ParseCertificate fail: %s", err.Error())
	}

	snByte := cert.SerialNumber.Bytes()

	for _, v := range snByte {
		sn += fmt.Sprintf("%02X", v)
	}

	return sn, nil

}
