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
	ID           int64  // NEW: Primary key
	Endpoint     string // UNIQUE but not primary key
	DiscoveredAt time.Time
	LastChecked  time.Time
	Status       int // 0=unknown, 1=online, 2=offline
	UserCount    int64
	UpdatedAt    time.Time
}

// PDSUpdate contains fields to update for a PDS
type PDSUpdate struct {
	Status       int
	LastChecked  time.Time
	ResponseTime float64 // milliseconds as float
	ScanData     *PDSScanData
}

// PDSScanData contains data from a PDS scan
type PDSScanData struct {
	ServerInfo interface{} `json:"server_info,omitempty"`
	DIDs       []string    `json:"dids,omitempty"`
	DIDCount   int         `json:"did_count"`
}

// PDSScan represents a historical PDS scan
type PDSScan struct {
	ID           int64
	PDSID        int64
	Status       int
	ResponseTime float64
	ScanData     *PDSScanData
	ScannedAt    time.Time
}

// Status constants
const (
	PDSStatusUnknown = 0
	PDSStatusOnline  = 1
	PDSStatusOffline = 2
)

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

// PLCBundle now uses bundle numbers
type PLCBundle struct {
	ID             int64
	BundleNumber   int // NEW: Sequential bundle number (hex filename)
	StartTime      time.Time
	EndTime        time.Time
	OperationCount int
	DIDs           []string
	FilePath       string
	FileSize       int64
	Compressed     bool
	CreatedAt      time.Time
}

// MempoolOperation represents an operation waiting to be bundled
type MempoolOperation struct {
	ID        int64
	DID       string
	Operation string // JSON of the full operation
	CID       string
	CreatedAt time.Time
	AddedAt   time.Time
}

// ScanCursor now stores bundle number
type ScanCursor struct {
	Source           string
	LastBundleNumber int // NEW: Last processed bundle number
	LastScanTime     time.Time
	RecordsProcessed int64
}
