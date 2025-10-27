package storage

import (
	"context"
	"fmt"
	"time"
)

// NewDatabase creates a database connection based on type
func NewDatabase(dbType, connectionString string) (Database, error) {
	switch dbType {
	case "postgres", "postgresql":
		return NewPostgresDB(connectionString)
	default:
		return nil, fmt.Errorf("unsupported database type: %s (supported: sqlite, postgres)", dbType)
	}
}

type Database interface {
	Close() error
	Migrate() error

	// Endpoint operations
	UpsertEndpoint(ctx context.Context, endpoint *Endpoint) error
	GetEndpoint(ctx context.Context, endpoint string, endpointType string) (*Endpoint, error)
	GetEndpoints(ctx context.Context, filter *EndpointFilter) ([]*Endpoint, error)
	EndpointExists(ctx context.Context, endpoint string, endpointType string) (bool, error)
	GetEndpointIDByEndpoint(ctx context.Context, endpoint string, endpointType string) (int64, error)
	GetEndpointScans(ctx context.Context, endpointID int64, limit int) ([]*EndpointScan, error)
	UpdateEndpointIPs(ctx context.Context, endpointID int64, ipv4, ipv6 string, resolvedAt time.Time) error
	SaveEndpointScan(ctx context.Context, scan *EndpointScan) error
	SetScanRetention(retention int)
	UpdateEndpointStatus(ctx context.Context, endpointID int64, update *EndpointUpdate) error
	UpdateEndpointServerDID(ctx context.Context, endpointID int64, serverDID string) error
	GetDuplicateEndpoints(ctx context.Context) (map[string][]string, error)

	// PDS virtual endpoints (created via JOINs)
	GetPDSList(ctx context.Context, filter *EndpointFilter) ([]*PDSListItem, error)
	GetPDSDetail(ctx context.Context, endpoint string) (*PDSDetail, error)
	GetPDSStats(ctx context.Context) (*PDSStats, error)
	GetCountryLeaderboard(ctx context.Context) ([]*CountryStats, error)
	GetVersionStats(ctx context.Context) ([]*VersionStats, error)

	// IP operations (IP as primary key)
	UpsertIPInfo(ctx context.Context, ip string, ipInfo map[string]interface{}) error
	GetIPInfo(ctx context.Context, ip string) (*IPInfo, error)
	ShouldUpdateIPInfo(ctx context.Context, ip string) (exists bool, needsUpdate bool, err error)

	// Cursor operations
	GetScanCursor(ctx context.Context, source string) (*ScanCursor, error)
	UpdateScanCursor(ctx context.Context, cursor *ScanCursor) error

	// Metrics
	StorePLCMetrics(ctx context.Context, metrics *PLCMetrics) error
	GetPLCMetrics(ctx context.Context, limit int) ([]*PLCMetrics, error)
	GetEndpointStats(ctx context.Context) (*EndpointStats, error)

	// DID operations
	UpsertDID(ctx context.Context, did string, bundleNum int, handle, pds string) error
	UpsertDIDFromMempool(ctx context.Context, did string, handle, pds string) error
	GetDIDRecord(ctx context.Context, did string) (*DIDRecord, error)
	GetDIDByHandle(ctx context.Context, handle string) (*DIDRecord, error) // NEW
	GetGlobalDIDInfo(ctx context.Context, did string) (*GlobalDIDInfo, error)
	AddBundleDIDs(ctx context.Context, bundleNum int, dids []string) error
	GetTotalDIDCount(ctx context.Context) (int64, error)

	// PDS Repo operations
	UpsertPDSRepos(ctx context.Context, endpointID int64, repos []PDSRepoData) error
	GetPDSRepos(ctx context.Context, endpointID int64, activeOnly bool, limit int, offset int) ([]*PDSRepo, error)
	GetReposByDID(ctx context.Context, did string) ([]*PDSRepo, error)
	GetPDSRepoStats(ctx context.Context, endpointID int64) (map[string]interface{}, error)

	// Internal
	GetTableSizes(ctx context.Context, schema string) ([]TableSizeInfo, error)
	GetIndexSizes(ctx context.Context, schema string) ([]IndexSizeInfo, error)
}
