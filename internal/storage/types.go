package storage

import "time"

// DID represents a decentralized identifier
type DID struct {
	DID         string
	PDSEndpoint string
	Handle      string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// PDS represents a Personal Data Server
type PDS struct {
	Endpoint     string
	DiscoveredAt time.Time
	LastChecked  time.Time
	Status       string
	ResponseTime int64
	ErrorMessage string
	ServerInfo   interface{}
	UserCount    int64
}

// PDSUpdate contains fields to update for a PDS
type PDSUpdate struct {
	Status       string
	LastChecked  time.Time
	ResponseTime int64
	ErrorMessage string
	ServerInfo   interface{}
}

// PDSFilter for querying PDS servers
type PDSFilter struct {
	Status       string
	MinUserCount int64
	Limit        int
	Offset       int
}

// PDSStats contains aggregate statistics about PDS servers
type PDSStats struct {
	TotalPDS        int64
	OnlinePDS       int64
	OfflinePDS      int64
	AvgResponseTime float64
	TotalDIDs       int64
}

// PLCMetrics contains metrics from PLC directory scans
type PLCMetrics struct {
	TotalDIDs    int64     `json:"total_dids"`
	TotalPDS     int64     `json:"total_pds"`
	UniquePDS    int64     `json:"unique_pds"`
	LastScanTime time.Time `json:"last_scan_time"`
	ScanDuration int64     `json:"scan_duration_ms"`
	ErrorCount   int       `json:"error_count"`
}

// ScanCursor tracks the last processed position in PLC directory
type ScanCursor struct {
	Source           string // "plc_directory"
	LastTimestamp    string // ISO 8601 datetime string like "2023-04-26T06:19:25.508Z"
	LastScanTime     time.Time
	RecordsProcessed int64
}

// PLCBundle represents a cached bundle of PLC operations
type PLCBundle struct {
	ID             int64
	StartTime      time.Time // First operation timestamp
	EndTime        time.Time // Last operation timestamp
	OperationCount int
	FilePath       string
	FileSize       int64
	Compressed     bool
	CreatedAt      time.Time
}
