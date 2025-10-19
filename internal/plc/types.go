package plc

import "time"

type PLCOperation struct {
	DID       string                 `json:"did"`
	Operation map[string]interface{} `json:"operation"`
	CID       string                 `json:"cid"`
	Nullified interface{}            `json:"nullified,omitempty"`
	CreatedAt time.Time              `json:"createdAt"`
}

// Helper method to check if nullified
func (op *PLCOperation) IsNullified() bool {
	if op.Nullified == nil {
		return false
	}

	switch v := op.Nullified.(type) {
	case bool:
		return v
	case string:
		return v != ""
	default:
		return false
	}
}

// Get nullifying CID if available
func (op *PLCOperation) GetNullifyingCID() string {
	if s, ok := op.Nullified.(string); ok {
		return s
	}
	return ""
}

type DIDDocument struct {
	Context            []string             `json:"@context"`
	ID                 string               `json:"id"`
	AlsoKnownAs        []string             `json:"alsoKnownAs"`
	VerificationMethod []VerificationMethod `json:"verificationMethod"`
	Service            []Service            `json:"service"`
}

type VerificationMethod struct {
	ID                 string `json:"id"`
	Type               string `json:"type"`
	Controller         string `json:"controller"`
	PublicKeyMultibase string `json:"publicKeyMultibase"`
}

type Service struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

// DIDHistoryEntry represents a single operation in DID history
type DIDHistoryEntry struct {
	Operation PLCOperation `json:"operation"`
	PLCBundle    string       `json:"plc_bundle,omitempty"`
}

// DIDHistory represents the full history of a DID
type DIDHistory struct {
	DID        string            `json:"did"`
	Current    *PLCOperation     `json:"current"`
	Operations []DIDHistoryEntry `json:"operations"`
}
