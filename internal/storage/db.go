package storage

import (
	"context"
	"time"
)

type Database interface {
	Close() error
	Migrate() error

	// PDS operations
	UpsertPDS(ctx context.Context, pds *PDS) error
	GetPDS(ctx context.Context, endpoint string) (*PDS, error)
	GetPDSByID(ctx context.Context, id int64) (*PDS, error) // NEW
	GetPDSServers(ctx context.Context, filter *PDSFilter) ([]*PDS, error)
	UpdatePDSStatus(ctx context.Context, pdsID int64, update *PDSUpdate) error // Changed to ID
	PDSExists(ctx context.Context, endpoint string) (bool, error)
	GetPDSIDByEndpoint(ctx context.Context, endpoint string) (int64, error) // NEW

	// PDS Scans - NEW
	GetPDSScans(ctx context.Context, pdsID int64, limit int) ([]*PDSScan, error)

	// Cursor operations
	GetScanCursor(ctx context.Context, source string) (*ScanCursor, error)
	UpdateScanCursor(ctx context.Context, cursor *ScanCursor) error

	// Bundle operations
	CreateBundle(ctx context.Context, bundle *PLCBundle) error
	GetBundle(ctx context.Context, afterTime time.Time) (*PLCBundle, error)
	GetBundleByID(ctx context.Context, bundleID int64) (*PLCBundle, error)
	GetBundles(ctx context.Context, limit int) ([]*PLCBundle, error)
	GetBundlesForDID(ctx context.Context, did string) ([]*PLCBundle, error)
	GetBundleStats(ctx context.Context) (int64, int64, error)

	// Metrics
	StorePLCMetrics(ctx context.Context, metrics *PLCMetrics) error
	GetPLCMetrics(ctx context.Context, limit int) ([]*PLCMetrics, error)
	GetPDSStats(ctx context.Context) (*PDSStats, error)
}
