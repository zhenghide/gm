package util

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sm2"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

func PriKeyToPem(sm2PriKey interface{}) (pemPriKey string, err error) {
	priKeyStream, _ := x509.MarshalSm2PrivateKey(sm2PriKey.(*sm2.PrivateKey))
	fmt.Println("-----------------SM2私钥字节-----------------")
	fmt.Println(priKeyStream)
	fmt.Println("length:", len(priKeyStream))

	block := &pem.Block{
		Type:  "SM2 PRIVATE KEY",
		Bytes: priKeyStream,
	}

	priKey := bytes.NewBuffer(make([]byte, 0))
	err = pem.Encode(priKey, block)
	if err != nil {
		return "", errors.New("Encode failed")
	}
	pemPriKey = priKey.String()

	return pemPriKey, nil
}

func DerKeyToPem(keyBytes []byte) (pemPriKey string, err error) {
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}

	priKey := bytes.NewBuffer(make([]byte, 0))
	err = pem.Encode(priKey, block)
	if err != nil {

		return "", errors.New("Encode failed")
	}
	pemPriKey = priKey.String()

	return pemPriKey, nil
}

func ECKeyToSM2Key(ecKey ecdsa.PublicKey) sm2.PublicKey {
	sm2PubKey := sm2.PublicKey{
		Curve: ecKey.Curve,
		X:     ecKey.X,
		Y:     ecKey.Y,
	}

	return sm2PubKey
}
