package storage

import (
	"context"
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

	// Metrics
	StorePLCMetrics(ctx context.Context, metrics *PLCMetrics) error
	GetPLCMetrics(ctx context.Context, limit int) ([]*PLCMetrics, error)
	GetPDSStats(ctx context.Context) (*PDSStats, error)
}
