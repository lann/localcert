package localcert

import (
	"gopkg.in/square/go-jose.v2"
)

type DomainRequest struct {
	AccountRequest []byte `json:"signedAccountRequest"`
}

type DomainResult struct {
	Domain string `json:"localcertDomain"`
}

type ProvisionRequest struct {
	PublicKey            *jose.JSONWebKey `json:"accountPublicKey"`
	AuthorizationRequest []byte           `json:"signedAuthorizationRequest"`
}

type ProvisionResult struct {
	AuthorizationURL        string `json:"authorizationURL"`
	ProvisionedChallengeURL string `json:"provisionedChallengeURL"`
}
