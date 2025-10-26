package plc

import "strings"

// MaxHandleLength is the maximum allowed handle length for database storage
const MaxHandleLength = 500

// ExtractHandle safely extracts the handle from a PLC operation
func ExtractHandle(op *PLCOperation) string {
	if op == nil || op.Operation == nil {
		return ""
	}

	// Get "alsoKnownAs"
	aka, ok := op.Operation["alsoKnownAs"].([]interface{})
	if !ok {
		return ""
	}

	// Find the handle (e.g., "at://handle.bsky.social")
	for _, item := range aka {
		if handle, ok := item.(string); ok {
			if strings.HasPrefix(handle, "at://") {
				return strings.TrimPrefix(handle, "at://")
			}
		}
	}
	return ""
}

// ValidateHandle checks if a handle is valid for database storage
// Returns empty string if handle is too long
func ValidateHandle(handle string) string {
	if len(handle) > MaxHandleLength {
		return ""
	}
	return handle
}

// ExtractPDS safely extracts the PDS endpoint from a PLC operation
func ExtractPDS(op *PLCOperation) string {
	if op == nil || op.Operation == nil {
		return ""
	}

	// Get "services"
	services, ok := op.Operation["services"].(map[string]interface{})
	if !ok {
		return ""
	}

	// Get "atproto_pds"
	pdsService, ok := services["atproto_pds"].(map[string]interface{})
	if !ok {
		return ""
	}

	// Get "endpoint"
	if endpoint, ok := pdsService["endpoint"].(string); ok {
		return endpoint
	}

	return ""
}

// DIDInfo contains extracted metadata from a PLC operation
type DIDInfo struct {
	Handle string
	PDS    string
}

// ExtractDIDInfo extracts both handle and PDS from an operation
func ExtractDIDInfo(op *PLCOperation) DIDInfo {
	return DIDInfo{
		Handle: ExtractHandle(op),
		PDS:    ExtractPDS(op),
	}
}

// ExtractDIDInfoMap creates a map of DID -> info from operations
// Processes in reverse order to get the latest state for each DID
func ExtractDIDInfoMap(ops []PLCOperation) map[string]DIDInfo {
	infoMap := make(map[string]DIDInfo)

	// Process in reverse to get latest state
	for i := len(ops) - 1; i >= 0; i-- {
		op := ops[i]
		if _, exists := infoMap[op.DID]; !exists {
			infoMap[op.DID] = ExtractDIDInfo(&op)
		}
	}

	return infoMap
}
