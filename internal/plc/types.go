package plc

import (
	plclib "github.com/atscan/plcbundle/plc"
)

// Re-export library types
type PLCOperation = plclib.PLCOperation
type DIDDocument = plclib.DIDDocument
type Client = plclib.Client
type ExportOptions = plclib.ExportOptions

// Keep your custom types
const BUNDLE_SIZE = 10000

type DIDHistoryEntry struct {
	Operation PLCOperation `json:"operation"`
	PLCBundle string       `json:"plc_bundle,omitempty"`
}

type DIDHistory struct {
	DID        string            `json:"did"`
	Current    *PLCOperation     `json:"current"`
	Operations []DIDHistoryEntry `json:"operations"`
}

type EndpointInfo struct {
	Type     string
	Endpoint string
}
