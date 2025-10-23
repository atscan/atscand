package storage

import (
	"fmt"
	"path/filepath"
	"time"
)

// DID represents a decentralized identifier
type DID struct {
	DID         string
	PDSEndpoint string
	Handle      string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Endpoint represents any AT Protocol service endpoint
type Endpoint struct {
	ID           int64
	EndpointType string // "pds", "labeler", etc.
	Endpoint     string
	DiscoveredAt time.Time
	LastChecked  time.Time
	Status       int
	UserCount    int64
	IP           string
	IPInfo       map[string]interface{}
	UpdatedAt    time.Time
}

// EndpointUpdate contains fields to update for an Endpoint
type EndpointUpdate struct {
	Status       int
	LastChecked  time.Time
	ResponseTime float64
	ScanData     *EndpointScanData
}

// EndpointScanData contains data from an endpoint scan
type EndpointScanData struct {
	ServerInfo interface{} `json:"server_info,omitempty"`
	DIDs       []string    `json:"dids,omitempty"`
	DIDCount   int         `json:"did_count"`
	Metadata   interface{} `json:"metadata,omitempty"` // Type-specific metadata
}

// EndpointScan represents a historical endpoint scan
type EndpointScan struct {
	ID           int64
	EndpointID   int64
	Status       int
	ResponseTime float64
	ScanData     *EndpointScanData
	ScannedAt    time.Time
}

// Status constants
const (
	PDSStatusUnknown = 0
	PDSStatusOnline  = 1
	PDSStatusOffline = 2
)

// Endpoint status constants (aliases for compatibility)
const (
	EndpointStatusUnknown = PDSStatusUnknown
	EndpointStatusOnline  = PDSStatusOnline
	EndpointStatusOffline = PDSStatusOffline
)

// EndpointFilter for querying endpoints
type EndpointFilter struct {
	Type         string // "pds", "labeler", etc.
	Status       string
	MinUserCount int64
	Limit        int
	Offset       int
}

// EndpointStats contains aggregate statistics about endpoints
type EndpointStats struct {
	TotalEndpoints   int64            `json:"total_endpoints"`
	ByType           map[string]int64 `json:"by_type"`
	OnlineEndpoints  int64            `json:"online_endpoints"`
	OfflineEndpoints int64            `json:"offline_endpoints"`
	AvgResponseTime  float64          `json:"avg_response_time"`
	TotalDIDs        int64            `json:"total_dids"` // Only for PDS
}

// Legacy type aliases for backward compatibility in code
type PDS = Endpoint
type PDSUpdate = EndpointUpdate
type PDSScanData = EndpointScanData
type PDSScan = EndpointScan
type PDSFilter = EndpointFilter
type PDSStats = EndpointStats

// PLCMetrics contains metrics from PLC directory scans
type PLCMetrics struct {
	TotalDIDs    int64     `json:"total_dids"`
	TotalPDS     int64     `json:"total_pds"`
	UniquePDS    int64     `json:"unique_pds"`
	LastScanTime time.Time `json:"last_scan_time"`
	ScanDuration int64     `json:"scan_duration_ms"`
	ErrorCount   int       `json:"error_count"`
}

// PLCBundle represents a cached bundle of PLC operations
type PLCBundle struct {
	BundleNumber               int
	StartTime                  time.Time
	EndTime                    time.Time
	BoundaryCIDs               []string
	DIDs                       []string
	Hash                       string
	CompressedHash             string
	CompressedSize             int64
	UncompressedSize           int64
	CumulativeCompressedSize   int64
	CumulativeUncompressedSize int64
	Cursor                     string
	PrevBundleHash             string
	Compressed                 bool
	CreatedAt                  time.Time
}

// GetFilePath returns the computed file path for this bundle
func (b *PLCBundle) GetFilePath(bundleDir string) string {
	return filepath.Join(bundleDir, fmt.Sprintf("%06d.jsonl.zst", b.BundleNumber))
}

// OperationCount returns the number of operations in a bundle (always 10000)
func (b *PLCBundle) OperationCount() int {
	return 10000
}

// MempoolOperation represents an operation waiting to be bundled
type MempoolOperation struct {
	ID        int64
	DID       string
	Operation string
	CID       string
	CreatedAt time.Time
	AddedAt   time.Time
}

// ScanCursor stores scanning progress
type ScanCursor struct {
	Source           string
	LastBundleNumber int
	LastScanTime     time.Time
	RecordsProcessed int64
}

// DIDRecord represents a DID entry in the database
type DIDRecord struct {
	DID           string    `json:"did"`
	BundleNumbers []int     `json:"bundle_numbers"`
	CreatedAt     time.Time `json:"created_at"`
}
