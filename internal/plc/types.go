package plc

import (
	"net/url"
	"strings"

	plclib "tangled.org/atscan.net/plcbundle/plc"
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

// PLCOpLabel holds metadata from the label CSV file
type PLCOpLabel struct {
	Bundle     int      `json:"bundle"`
	Position   int      `json:"position"`
	CID        string   `json:"cid"`
	Size       int      `json:"size"`
	Confidence float64  `json:"confidence"`
	Detectors  []string `json:"detectors"`
}

// validateEndpoint checks if endpoint is in correct format: https://<domain>
func validateEndpoint(endpoint string) bool {
	// Must not be empty
	if endpoint == "" {
		return false
	}

	// Must not have trailing slash
	if strings.HasSuffix(endpoint, "/") {
		return false
	}

	// Parse URL
	u, err := url.Parse(endpoint)
	if err != nil {
		return false
	}

	// Must use https scheme
	if u.Scheme != "https" {
		return false
	}

	// Must have a host
	if u.Host == "" {
		return false
	}

	// Must not have path (except empty)
	if u.Path != "" && u.Path != "/" {
		return false
	}

	// Must not have query parameters
	if u.RawQuery != "" {
		return false
	}

	// Must not have fragment
	if u.Fragment != "" {
		return false
	}

	return true
}
