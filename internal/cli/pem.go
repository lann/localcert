package cli

import (
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

const (
	certificatePEMType = "CERTIFICATE"
	privateKeyPEMType  = "PRIVATE KEY"
)

var errNotPEM = errors.New("no PEM data found")

func ReadPEMFile(name, pemType string) ([]byte, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errNotPEM
	}
	if block.Type != pemType {
		return nil, fmt.Errorf("unexpected PEM type %q", block.Type)
	}
	return block.Bytes, nil
}

func WritePEMFile(name, pemType string, content []byte) error {
	block := &pem.Block{Type: pemType, Bytes: content}
	return os.WriteFile(name, pem.EncodeToMemory(block), filePerm)
}
