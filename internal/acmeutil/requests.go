package acmeutil

import (
	"fmt"

	"gopkg.in/square/go-jose.v2"
)

type SignedRequest struct {
	Content  []byte
	KID, URL string

	jws *jose.JSONWebSignature
}

func ParseSignedRequest(body []byte) (*SignedRequest, error) {
	jws, err := jose.ParseSigned(string(body))
	if err != nil {
		return nil, fmt.Errorf("parse jws: %w", err)
	}

	if len(jws.Signatures) != 1 {
		return nil, fmt.Errorf("expected 1 signature got %d", len(jws.Signatures))
	}
	sig := jws.Signatures[0]

	url, ok := sig.Protected.ExtraHeaders["url"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid url %q", url)
	}

	return &SignedRequest{Content: body, KID: sig.Header.KeyID, URL: url, jws: jws}, nil
}

func (r *SignedRequest) UnsafePayload() []byte {
	return r.jws.UnsafePayloadWithoutVerification()
}

func (r *SignedRequest) Verify(publicKey interface{}) error {
	_, err := r.jws.Verify(publicKey)
	return err
}
