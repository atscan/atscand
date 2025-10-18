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
	GetPDSServers(ctx context.Context, filter *PDSFilter) ([]*PDS, error)
	UpdatePDSStatus(ctx context.Context, endpoint string, update *PDSUpdate) error
	PDSExists(ctx context.Context, endpoint string) (bool, error)

	// Cursor operations
	GetScanCursor(ctx context.Context, source string) (*ScanCursor, error)
	UpdateScanCursor(ctx context.Context, cursor *ScanCursor) error

	// Bundle operations
	CreateBundle(ctx context.Context, bundle *PLCBundle) error
	GetBundle(ctx context.Context, afterTime time.Time) (*PLCBundle, error)
	GetBundles(ctx context.Context, limit int) ([]*PLCBundle, error)
	GetBundleStats(ctx context.Context) (int64, int64, error)
	GetAllBundles(ctx context.Context) ([]*PLCBundle, error) // For DID search

	// Metrics
	StorePLCMetrics(ctx context.Context, metrics *PLCMetrics) error
	GetPLCMetrics(ctx context.Context, limit int) ([]*PLCMetrics, error)
	GetPDSStats(ctx context.Context) (*PDSStats, error)
}
