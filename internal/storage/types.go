package storage

import (
	"database/sql"
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
	EndpointType string
	Endpoint     string
	ServerDID    string
	DiscoveredAt time.Time
	LastChecked  time.Time
	Status       int
	IP           string
	IPv6         string // NEW
	IPResolvedAt time.Time
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
	ServerInfo interface{}            `json:"server_info,omitempty"`
	DIDs       []string               `json:"dids,omitempty"`
	DIDCount   int                    `json:"did_count"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// EndpointScan represents a historical endpoint scan
type EndpointScan struct {
	ID           int64
	EndpointID   int64
	Status       int
	ResponseTime float64
	UserCount    int64
	Version      string
	UsedIP       string // NEW: Track which IP was actually used
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
	Type            string // "pds", "labeler", etc.
	Status          string
	MinUserCount    int64
	OnlyStale       bool
	RecheckInterval time.Duration
	Random          bool // NEW: Return results in random order
	Limit           int
	Offset          int
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
	DIDCount                   int // Changed from DIDs []string
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

type PLCHistoryPoint struct {
	Date                   string `json:"date"`
	BundleNumber           int    `json:"last_bundle_number"`
	OperationCount         int    `json:"operations"`
	UncompressedSize       int64  `json:"size_uncompressed"`
	CompressedSize         int64  `json:"size_compressed"`
	CumulativeUncompressed int64  `json:"cumulative_uncompressed"`
	CumulativeCompressed   int64  `json:"cumulative_compressed"`
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
	Handle        string    `json:"handle,omitempty"`
	CurrentPDS    string    `json:"current_pds,omitempty"`
	LastOpAt      time.Time `json:"last_op_at,omitempty"`
	BundleNumbers []int     `json:"bundle_numbers"`
	CreatedAt     time.Time `json:"created_at"`
}

// GlobalDIDInfo consolidates DID data from PLC and PDS tables
type GlobalDIDInfo struct {
	DIDRecord            // Embeds all fields: DID, Handle, CurrentPDS, etc.
	HostingOn []*PDSRepo `json:"hosting_on"`
}

// IPInfo represents IP information (stored with IP as primary key)
type IPInfo struct {
	IP           string                 `json:"ip"`
	City         string                 `json:"city,omitempty"`
	Country      string                 `json:"country,omitempty"`
	CountryCode  string                 `json:"country_code,omitempty"`
	ASN          int                    `json:"asn,omitempty"`
	ASNOrg       string                 `json:"asn_org,omitempty"`
	IsDatacenter bool                   `json:"is_datacenter"`
	IsVPN        bool                   `json:"is_vpn"`
	IsCrawler    bool                   `json:"is_crawler"`
	IsTor        bool                   `json:"is_tor"`
	IsProxy      bool                   `json:"is_proxy"`
	Latitude     float32                `json:"latitude,omitempty"`
	Longitude    float32                `json:"longitude,omitempty"`
	RawData      map[string]interface{} `json:"raw_data,omitempty"`
	FetchedAt    time.Time              `json:"fetched_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
}

// IsHome returns true if this is a residential/home IP
// (not crawler, datacenter, tor, proxy, or vpn)
func (i *IPInfo) IsHome() bool {
	return !i.IsCrawler && !i.IsDatacenter && !i.IsTor && !i.IsProxy && !i.IsVPN
}

// PDSListItem is a virtual type created by JOIN for /pds endpoint
type PDSListItem struct {
	// From endpoints table
	ID           int64
	Endpoint     string
	ServerDID    string
	DiscoveredAt time.Time
	LastChecked  time.Time
	Status       int
	IP           string
	IPv6         string // NEW

	// From latest endpoint_scans (via JOIN)
	LatestScan *struct {
		UserCount    int
		ResponseTime float64
		Version      string
		ScannedAt    time.Time
	}

	// From ip_infos table (via JOIN on endpoints.ip)
	IPInfo *IPInfo
}

// PDSDetail is extended version for /pds/{endpoint}
type PDSDetail struct {
	PDSListItem

	// Additional data from latest scan
	LatestScan *struct {
		UserCount    int
		ResponseTime float64
		Version      string
		ServerInfo   interface{} // Full server description
		ScannedAt    time.Time
	}

	// NEW: Aliases (other domains pointing to same server)
	Aliases   []string `json:"aliases,omitempty"`
	IsPrimary bool     `json:"is_primary"`
}

type CountryStats struct {
	Country           string  `json:"country"`
	CountryCode       string  `json:"country_code"`
	ActivePDSCount    int64   `json:"active_pds_count"`
	PDSPercentage     float64 `json:"pds_percentage"`
	TotalUsers        int64   `json:"total_users"`
	UsersPercentage   float64 `json:"users_percentage"`
	AvgResponseTimeMS float64 `json:"avg_response_time_ms"`
}

type VersionStats struct {
	Version         string    `json:"version"`
	PDSCount        int64     `json:"pds_count"`
	Percentage      float64   `json:"percentage"`
	PercentageText  string    `json:"percentage_text"`
	TotalUsers      int64     `json:"total_users"`
	UsersPercentage float64   `json:"users_percentage"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
}

type PDSRepo struct {
	ID         int64     `json:"id"`
	EndpointID int64     `json:"endpoint_id"`
	Endpoint   string    `json:"endpoint,omitempty"`
	DID        string    `json:"did"`
	Head       string    `json:"head,omitempty"`
	Rev        string    `json:"rev,omitempty"`
	Active     bool      `json:"active"`
	Status     string    `json:"status,omitempty"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type PDSRepoData struct {
	DID    string
	Head   string
	Rev    string
	Active bool
	Status string
}

type DIDBackfillInfo struct {
	DID           string
	LastBundleNum int
}

type DIDStateUpdateData struct {
	DID    string
	Handle sql.NullString // Use sql.NullString for potential NULLs
	PDS    sql.NullString
	OpTime time.Time
}

// TableSizeInfo holds size information for a database table.
type TableSizeInfo struct {
	TableName      string `json:"table_name"`
	TotalBytes     int64  `json:"total_bytes"`      // Raw bytes
	TableHeapBytes int64  `json:"table_heap_bytes"` // Raw bytes
	IndexesBytes   int64  `json:"indexes_bytes"`    // Raw bytes
}

// IndexSizeInfo holds size information for a database index.
type IndexSizeInfo struct {
	IndexName  string `json:"index_name"`
	TableName  string `json:"table_name"`
	IndexBytes int64  `json:"index_bytes"` // Raw bytes
}
