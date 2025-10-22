package storage

import (
	"context"
	"time"
)

type Database interface {
	Close() error
	Migrate() error

	// Endpoint operations (renamed from PDS)
	UpsertEndpoint(ctx context.Context, endpoint *Endpoint) error
	GetEndpoint(ctx context.Context, endpoint string, endpointType string) (*Endpoint, error)
	GetEndpointByID(ctx context.Context, id int64) (*Endpoint, error)
	GetEndpoints(ctx context.Context, filter *EndpointFilter) ([]*Endpoint, error)
	UpdateEndpointStatus(ctx context.Context, endpointID int64, update *EndpointUpdate) error
	EndpointExists(ctx context.Context, endpoint string, endpointType string) (bool, error)
	GetEndpointIDByEndpoint(ctx context.Context, endpoint string, endpointType string) (int64, error)
	GetEndpointScans(ctx context.Context, endpointID int64, limit int) ([]*EndpointScan, error)

	// Cursor operations
	GetScanCursor(ctx context.Context, source string) (*ScanCursor, error)
	UpdateScanCursor(ctx context.Context, cursor *ScanCursor) error

	// Bundle operations
	CreateBundle(ctx context.Context, bundle *PLCBundle) error
	GetBundleByNumber(ctx context.Context, bundleNumber int) (*PLCBundle, error)
	GetBundles(ctx context.Context, limit int) ([]*PLCBundle, error)
	GetBundlesForDID(ctx context.Context, did string) ([]*PLCBundle, error)
	GetBundleStats(ctx context.Context) (int64, int64, error)
	GetLastBundleNumber(ctx context.Context) (int, error)
	GetBundleForTimestamp(ctx context.Context, afterTime time.Time) (int, error)

	// Mempool operations
	AddToMempool(ctx context.Context, ops []MempoolOperation) error
	GetMempoolCount(ctx context.Context) (int, error)
	GetMempoolOperations(ctx context.Context, limit int) ([]MempoolOperation, error)
	DeleteFromMempool(ctx context.Context, ids []int64) error
	GetFirstMempoolOperation(ctx context.Context) (*MempoolOperation, error)
	GetLastMempoolOperation(ctx context.Context) (*MempoolOperation, error)
	GetMempoolUniqueDIDCount(ctx context.Context) (int, error)
	GetMempoolUncompressedSize(ctx context.Context) (int64, error)

	// Metrics
	StorePLCMetrics(ctx context.Context, metrics *PLCMetrics) error
	GetPLCMetrics(ctx context.Context, limit int) ([]*PLCMetrics, error)
	GetEndpointStats(ctx context.Context) (*EndpointStats, error)
}
