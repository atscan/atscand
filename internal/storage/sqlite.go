package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type SQLiteDB struct {
	db *sql.DB
}

func NewSQLiteDB(path string) (*SQLiteDB, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	// Enable WAL mode for better concurrency
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return nil, err
	}

	return &SQLiteDB{db: db}, nil
}

func (s *SQLiteDB) Close() error {
	return s.db.Close()
}

func (s *SQLiteDB) Migrate() error {
	schema := `
    -- Endpoints table (replaces pds_servers)
    CREATE TABLE IF NOT EXISTS endpoints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        endpoint_type TEXT NOT NULL DEFAULT 'pds',
        endpoint TEXT NOT NULL,
        discovered_at TIMESTAMP NOT NULL,
        last_checked TIMESTAMP,
        status INTEGER DEFAULT 0,
        user_count INTEGER DEFAULT 0,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(endpoint_type, endpoint)
    );

    CREATE INDEX IF NOT EXISTS idx_endpoints_type_endpoint ON endpoints(endpoint_type, endpoint);
    CREATE INDEX IF NOT EXISTS idx_endpoints_status ON endpoints(status);
    CREATE INDEX IF NOT EXISTS idx_endpoints_type ON endpoints(endpoint_type);
    CREATE INDEX IF NOT EXISTS idx_endpoints_user_count ON endpoints(user_count);

    -- Keep pds_scans table (or rename to endpoint_scans later)
    CREATE TABLE IF NOT EXISTS pds_scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pds_id INTEGER NOT NULL,
        status INTEGER NOT NULL,
        response_time REAL,
        scan_data TEXT,
        scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (pds_id) REFERENCES endpoints(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_pds_scans_pds_id ON pds_scans(pds_id);
    CREATE INDEX IF NOT EXISTS idx_pds_scans_scanned_at ON pds_scans(scanned_at);

    -- Metrics
    CREATE TABLE IF NOT EXISTS plc_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        total_dids INTEGER,
        total_pds INTEGER,
        unique_pds INTEGER,
        scan_duration_ms INTEGER,
        error_count INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    -- Scan cursors with bundle number
    CREATE TABLE IF NOT EXISTS scan_cursors (
        source TEXT PRIMARY KEY,
        last_bundle_number INTEGER DEFAULT 0,
        last_scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        records_processed INTEGER DEFAULT 0
    );

    -- Bundles with dual hashing
    CREATE TABLE IF NOT EXISTS plc_bundles (
        bundle_number INTEGER PRIMARY KEY,
        start_time TIMESTAMP NOT NULL,
        end_time TIMESTAMP NOT NULL,
        dids TEXT NOT NULL,
        hash TEXT NOT NULL,
        compressed_hash TEXT NOT NULL,
        compressed_size INTEGER NOT NULL,
        uncompressed_size INTEGER NOT NULL,     -- NEW
        cursor TEXT,                             -- NEW
        prev_bundle_hash TEXT,
        compressed BOOLEAN DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_plc_bundles_time ON plc_bundles(start_time, end_time);
    CREATE INDEX IF NOT EXISTS idx_plc_bundles_hash ON plc_bundles(hash);
    CREATE INDEX IF NOT EXISTS idx_plc_bundles_prev ON plc_bundles(prev_bundle_hash);

    -- NEW: Mempool for pending operations
	CREATE TABLE IF NOT EXISTS plc_mempool (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		did TEXT NOT NULL,
		operation TEXT NOT NULL,
		cid TEXT NOT NULL UNIQUE,  -- ✅ Add UNIQUE constraint
		created_at TIMESTAMP NOT NULL,
		added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

    CREATE INDEX IF NOT EXISTS idx_mempool_created_at ON plc_mempool(created_at);
    CREATE INDEX IF NOT EXISTS idx_mempool_did ON plc_mempool(did);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_mempool_cid ON plc_mempool(cid);
    `

	_, err := s.db.Exec(schema)
	return err
}

// GetBundleByNumber
func (s *SQLiteDB) GetBundleByNumber(ctx context.Context, bundleNumber int) (*PLCBundle, error) {
	query := `
        SELECT bundle_number, start_time, end_time, dids, hash, compressed_hash, 
               compressed_size, uncompressed_size, cursor, prev_bundle_hash, compressed, created_at
        FROM plc_bundles
        WHERE bundle_number = ?
    `

	var bundle PLCBundle
	var didsJSON string
	var prevHash sql.NullString
	var cursor sql.NullString

	err := s.db.QueryRowContext(ctx, query, bundleNumber).Scan(
		&bundle.BundleNumber, &bundle.StartTime, &bundle.EndTime,
		&didsJSON, &bundle.Hash, &bundle.CompressedHash,
		&bundle.CompressedSize, &bundle.UncompressedSize, &cursor,
		&prevHash, &bundle.Compressed, &bundle.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	if prevHash.Valid {
		bundle.PrevBundleHash = prevHash.String
	}
	if cursor.Valid {
		bundle.Cursor = cursor.String
	}

	json.Unmarshal([]byte(didsJSON), &bundle.DIDs)
	return &bundle, nil
}

// GetBundleForTimestamp finds the bundle that should contain operations at or after the given time
func (s *SQLiteDB) GetBundleForTimestamp(ctx context.Context, afterTime time.Time) (int, error) {
	query := `
		SELECT bundle_number 
		FROM plc_bundles 
		WHERE start_time <= ? AND end_time >= ?
		ORDER BY bundle_number ASC 
		LIMIT 1
	`

	var bundleNum int
	err := s.db.QueryRowContext(ctx, query, afterTime, afterTime).Scan(&bundleNum)
	if err == sql.ErrNoRows {
		// No exact match, find the closest bundle before this time
		query = `
			SELECT bundle_number 
			FROM plc_bundles 
			WHERE end_time < ?
			ORDER BY bundle_number DESC 
			LIMIT 1
		`
		err = s.db.QueryRowContext(ctx, query, afterTime).Scan(&bundleNum)
		if err == sql.ErrNoRows {
			return 1, nil // Start from first bundle
		}
		if err != nil {
			return 0, err
		}
		return bundleNum, nil // Return the bundle just before
	}
	if err != nil {
		return 0, err
	}

	return bundleNum, nil
}

// GetLastBundleNumber gets the highest bundle number
func (s *SQLiteDB) GetLastBundleNumber(ctx context.Context) (int, error) {
	query := "SELECT COALESCE(MAX(bundle_number), 0) FROM plc_bundles"
	var num int
	err := s.db.QueryRowContext(ctx, query).Scan(&num)
	return num, err
}

// AddToMempool adds operations to the mempool
func (s *SQLiteDB) AddToMempool(ctx context.Context, ops []MempoolOperation) error {
	if len(ops) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// ✅ Use ON CONFLICT to skip duplicates
	stmt, err := tx.PrepareContext(ctx, `
        INSERT INTO plc_mempool (did, operation, cid, created_at) 
        VALUES (?, ?, ?, ?)
        ON CONFLICT(cid) DO NOTHING
    `)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, op := range ops {
		_, err := stmt.ExecContext(ctx, op.DID, op.Operation, op.CID, op.CreatedAt)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// GetMempoolCount returns number of operations in mempool
func (s *SQLiteDB) GetMempoolCount(ctx context.Context) (int, error) {
	query := "SELECT COUNT(*) FROM plc_mempool"
	var count int
	err := s.db.QueryRowContext(ctx, query).Scan(&count)
	return count, err
}

// GetMempoolOperations retrieves operations from mempool ordered by timestamp
func (s *SQLiteDB) GetMempoolOperations(ctx context.Context, limit int) ([]MempoolOperation, error) {
	query := `
        SELECT id, did, operation, cid, created_at, added_at
        FROM plc_mempool
        ORDER BY created_at ASC
        LIMIT ?
    `

	rows, err := s.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ops []MempoolOperation
	for rows.Next() {
		var op MempoolOperation
		err := rows.Scan(&op.ID, &op.DID, &op.Operation, &op.CID, &op.CreatedAt, &op.AddedAt)
		if err != nil {
			return nil, err
		}
		ops = append(ops, op)
	}

	return ops, rows.Err()
}

// DeleteFromMempool removes operations from mempool
func (s *SQLiteDB) DeleteFromMempool(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}

	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		placeholders[i] = "?"
		args[i] = id
	}

	query := fmt.Sprintf("DELETE FROM plc_mempool WHERE id IN (%s)",
		strings.Join(placeholders, ","))

	_, err := s.db.ExecContext(ctx, query, args...)
	return err
}

// GetFirstMempoolOperation retrieves the oldest operation from mempool
func (s *SQLiteDB) GetFirstMempoolOperation(ctx context.Context) (*MempoolOperation, error) {
	query := `
        SELECT id, did, operation, cid, created_at, added_at
        FROM plc_mempool
        ORDER BY created_at ASC, id ASC
        LIMIT 1
    `

	var op MempoolOperation
	err := s.db.QueryRowContext(ctx, query).Scan(
		&op.ID, &op.DID, &op.Operation, &op.CID, &op.CreatedAt, &op.AddedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil // No operations in mempool
	}
	if err != nil {
		return nil, err
	}

	return &op, nil
}

// GetLastMempoolOperation retrieves the most recent operation from mempool
func (s *SQLiteDB) GetLastMempoolOperation(ctx context.Context) (*MempoolOperation, error) {
	query := `
        SELECT id, did, operation, cid, created_at, added_at
        FROM plc_mempool
        ORDER BY created_at DESC, id DESC
        LIMIT 1
    `

	var op MempoolOperation
	err := s.db.QueryRowContext(ctx, query).Scan(
		&op.ID, &op.DID, &op.Operation, &op.CID, &op.CreatedAt, &op.AddedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil // No operations in mempool
	}
	if err != nil {
		return nil, err
	}

	return &op, nil
}

func (s *SQLiteDB) CreateBundle(ctx context.Context, bundle *PLCBundle) error {
	didsJSON, err := json.Marshal(bundle.DIDs)
	if err != nil {
		return err
	}

	query := `
        INSERT INTO plc_bundles (
            bundle_number, start_time, end_time, dids, 
            hash, compressed_hash, compressed_size, uncompressed_size, cursor, prev_bundle_hash, compressed
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(bundle_number) DO UPDATE SET
            start_time = excluded.start_time,
            end_time = excluded.end_time,
            dids = excluded.dids,
            hash = excluded.hash,
            compressed_hash = excluded.compressed_hash,
            compressed_size = excluded.compressed_size,
            uncompressed_size = excluded.uncompressed_size,
            cursor = excluded.cursor,
            prev_bundle_hash = excluded.prev_bundle_hash,
            compressed = excluded.compressed
    `
	_, err = s.db.ExecContext(ctx, query,
		bundle.BundleNumber, bundle.StartTime, bundle.EndTime,
		string(didsJSON), bundle.Hash, bundle.CompressedHash,
		bundle.CompressedSize, bundle.UncompressedSize, bundle.Cursor,
		bundle.PrevBundleHash, bundle.Compressed,
	)

	return err
}

// GetMempoolUniqueDIDCount returns the number of unique DIDs in mempool
func (s *SQLiteDB) GetMempoolUniqueDIDCount(ctx context.Context) (int, error) {
	query := "SELECT COUNT(DISTINCT did) FROM plc_mempool"
	var count int
	err := s.db.QueryRowContext(ctx, query).Scan(&count)
	return count, err
}

// GetMempoolUncompressedSize returns total uncompressed size of all operations
func (s *SQLiteDB) GetMempoolUncompressedSize(ctx context.Context) (int64, error) {
	query := "SELECT COALESCE(SUM(LENGTH(operation)), 0) FROM plc_mempool"
	var size int64
	err := s.db.QueryRowContext(ctx, query).Scan(&size)
	return size, err
}

// GetBundles
func (s *SQLiteDB) GetBundles(ctx context.Context, limit int) ([]*PLCBundle, error) {
	query := `
        SELECT bundle_number, start_time, end_time, dids, hash, compressed_hash, compressed_size, prev_bundle_hash, compressed, created_at
        FROM plc_bundles
        ORDER BY bundle_number DESC
        LIMIT ?
    `

	rows, err := s.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return s.scanBundles(rows)
}

// GetBundlesForDID
func (s *SQLiteDB) GetBundlesForDID(ctx context.Context, did string) ([]*PLCBundle, error) {
	query := `
        SELECT bundle_number, start_time, end_time, dids, hash, compressed_hash, compressed_size, prev_bundle_hash, compressed, created_at
        FROM plc_bundles
        WHERE EXISTS (
            SELECT 1 FROM json_each(dids) 
            WHERE json_each.value = ?
        )
        ORDER BY bundle_number ASC
    `

	rows, err := s.db.QueryContext(ctx, query, did)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return s.scanBundles(rows)
}

// GetBundle retrieves bundle by time (if needed, otherwise can be removed)
func (s *SQLiteDB) GetBundle(ctx context.Context, afterTime time.Time) (*PLCBundle, error) {
	var query string
	var args []interface{}

	if afterTime.IsZero() {
		query = `
            SELECT bundle_number, start_time, end_time, dids, hash, compressed_hash, compressed_size, prev_bundle_hash, compressed, created_at
            FROM plc_bundles
            ORDER BY start_time ASC
            LIMIT 1
        `
		args = []interface{}{}
	} else {
		query = `
            SELECT bundle_number, start_time, end_time, dids, hash, compressed_hash, compressed_size, prev_bundle_hash, compressed, created_at
            FROM plc_bundles
            WHERE start_time >= ?
            ORDER BY start_time ASC
            LIMIT 1
        `
		args = []interface{}{afterTime}
	}

	var bundle PLCBundle
	var didsJSON string
	var prevHash sql.NullString

	err := s.db.QueryRowContext(ctx, query, args...).Scan(
		&bundle.BundleNumber,
		&bundle.StartTime,
		&bundle.EndTime,
		&didsJSON,
		&bundle.Hash,           // Uncompressed hash
		&bundle.CompressedHash, // Compressed hash
		&bundle.CompressedSize, // Compressed size (not FileSize!)
		&prevHash,              // Previous bundle hash
		&bundle.Compressed,
		&bundle.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if prevHash.Valid {
		bundle.PrevBundleHash = prevHash.String
	}

	json.Unmarshal([]byte(didsJSON), &bundle.DIDs)
	return &bundle, nil
}

func (s *SQLiteDB) scanBundles(rows *sql.Rows) ([]*PLCBundle, error) {
	var bundles []*PLCBundle

	for rows.Next() {
		var bundle PLCBundle
		var didsJSON string
		var prevHash sql.NullString
		var cursor sql.NullString

		if err := rows.Scan(
			&bundle.BundleNumber,
			&bundle.StartTime,
			&bundle.EndTime,
			&didsJSON,
			&bundle.Hash,
			&bundle.CompressedHash,
			&bundle.CompressedSize,
			&bundle.UncompressedSize,
			&cursor,
			&prevHash,
			&bundle.Compressed,
			&bundle.CreatedAt,
		); err != nil {
			return nil, err
		}

		if prevHash.Valid {
			bundle.PrevBundleHash = prevHash.String
		}
		if cursor.Valid {
			bundle.Cursor = cursor.String
		}

		json.Unmarshal([]byte(didsJSON), &bundle.DIDs)
		bundles = append(bundles, &bundle)
	}

	return bundles, rows.Err()
}

// GetBundleStats - update to use compressed_size
func (s *SQLiteDB) GetBundleStats(ctx context.Context) (int64, int64, error) {
	query := `
        SELECT COUNT(*), COALESCE(SUM(compressed_size), 0)
        FROM plc_bundles
    `

	var count, totalSize int64
	err := s.db.QueryRowContext(ctx, query).Scan(&count, &totalSize)
	return count, totalSize, err
}

// UpsertEndpoint inserts or updates an endpoint
func (s *SQLiteDB) UpsertEndpoint(ctx context.Context, endpoint *Endpoint) error {
	query := `
        INSERT INTO endpoints (endpoint_type, endpoint, discovered_at, last_checked, status)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(endpoint_type, endpoint) DO UPDATE SET
            last_checked = excluded.last_checked
        RETURNING id
    `
	err := s.db.QueryRowContext(ctx, query,
		endpoint.EndpointType, endpoint.Endpoint, endpoint.DiscoveredAt,
		endpoint.LastChecked, endpoint.Status).Scan(&endpoint.ID)
	return err
}

// EndpointExists checks if an endpoint already exists
func (s *SQLiteDB) EndpointExists(ctx context.Context, endpoint string, endpointType string) (bool, error) {
	query := "SELECT EXISTS(SELECT 1 FROM endpoints WHERE endpoint = ? AND endpoint_type = ?)"
	var exists bool
	err := s.db.QueryRowContext(ctx, query, endpoint, endpointType).Scan(&exists)
	return exists, err
}

// GetEndpointIDByEndpoint gets the ID for an endpoint
func (s *SQLiteDB) GetEndpointIDByEndpoint(ctx context.Context, endpoint string, endpointType string) (int64, error) {
	query := "SELECT id FROM endpoints WHERE endpoint = ? AND endpoint_type = ?"
	var id int64
	err := s.db.QueryRowContext(ctx, query, endpoint, endpointType).Scan(&id)
	return id, err
}

// GetEndpoint retrieves an endpoint by endpoint string and type
func (s *SQLiteDB) GetEndpoint(ctx context.Context, endpoint string, endpointType string) (*Endpoint, error) {
	query := `
        SELECT id, endpoint_type, endpoint, discovered_at, last_checked, status, user_count, updated_at
        FROM endpoints 
        WHERE endpoint = ? AND endpoint_type = ?
    `

	var ep Endpoint
	var lastChecked sql.NullTime

	err := s.db.QueryRowContext(ctx, query, endpoint, endpointType).Scan(
		&ep.ID, &ep.EndpointType, &ep.Endpoint, &ep.DiscoveredAt, &lastChecked,
		&ep.Status, &ep.UserCount, &ep.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	if lastChecked.Valid {
		ep.LastChecked = lastChecked.Time
	}

	return &ep, nil
}

// GetEndpointByID retrieves an endpoint by ID
func (s *SQLiteDB) GetEndpointByID(ctx context.Context, id int64) (*Endpoint, error) {
	query := `
        SELECT id, endpoint_type, endpoint, discovered_at, last_checked, status, user_count, updated_at
        FROM endpoints 
        WHERE id = ?
    `

	var ep Endpoint
	var lastChecked sql.NullTime

	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&ep.ID, &ep.EndpointType, &ep.Endpoint, &ep.DiscoveredAt, &lastChecked,
		&ep.Status, &ep.UserCount, &ep.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	if lastChecked.Valid {
		ep.LastChecked = lastChecked.Time
	}

	return &ep, nil
}

// GetEndpoints retrieves multiple endpoints
func (s *SQLiteDB) GetEndpoints(ctx context.Context, filter *EndpointFilter) ([]*Endpoint, error) {
	query := `
        SELECT id, endpoint_type, endpoint, discovered_at, last_checked, status, user_count, updated_at
        FROM endpoints
        WHERE 1=1
    `
	args := []interface{}{}

	if filter != nil {
		if filter.Type != "" {
			query += " AND endpoint_type = ?"
			args = append(args, filter.Type)
		}
		if filter.Status != "" {
			statusInt := EndpointStatusUnknown
			switch filter.Status {
			case "online":
				statusInt = EndpointStatusOnline
			case "offline":
				statusInt = EndpointStatusOffline
			}
			query += " AND status = ?"
			args = append(args, statusInt)
		}
		if filter.MinUserCount > 0 {
			query += " AND user_count >= ?"
			args = append(args, filter.MinUserCount)
		}
	}

	query += " ORDER BY user_count DESC"

	if filter != nil && filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d OFFSET %d", filter.Limit, filter.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var endpoints []*Endpoint
	for rows.Next() {
		var ep Endpoint
		var lastChecked sql.NullTime

		err := rows.Scan(
			&ep.ID, &ep.EndpointType, &ep.Endpoint, &ep.DiscoveredAt, &lastChecked,
			&ep.Status, &ep.UserCount, &ep.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		if lastChecked.Valid {
			ep.LastChecked = lastChecked.Time
		}

		endpoints = append(endpoints, &ep)
	}

	return endpoints, rows.Err()
}

// UpdateEndpointStatus updates the status and creates a scan record
func (s *SQLiteDB) UpdateEndpointStatus(ctx context.Context, endpointID int64, update *EndpointUpdate) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Calculate user count from scan data
	userCount := 0
	if update.ScanData != nil {
		userCount = update.ScanData.DIDCount
	}

	// Update main endpoints record
	query := `
        UPDATE endpoints 
        SET status = ?, last_checked = ?, user_count = ?, updated_at = ?
        WHERE id = ?
    `
	_, err = tx.ExecContext(ctx, query, update.Status, update.LastChecked, userCount, time.Now(), endpointID)
	if err != nil {
		return err
	}

	// Marshal scan data
	var scanDataJSON []byte
	if update.ScanData != nil {
		scanDataJSON, _ = json.Marshal(update.ScanData)
	}

	// Insert scan history (reuse pds_scans table or rename it to endpoint_scans)
	scanQuery := `
        INSERT INTO pds_scans (pds_id, status, response_time, scan_data)
        VALUES (?, ?, ?, ?)
    `
	_, err = tx.ExecContext(ctx, scanQuery, endpointID, update.Status, update.ResponseTime, string(scanDataJSON))
	if err != nil {
		return err
	}

	return tx.Commit()
}

// GetEndpointScans retrieves scan history for an endpoint
func (s *SQLiteDB) GetEndpointScans(ctx context.Context, endpointID int64, limit int) ([]*EndpointScan, error) {
	query := `
        SELECT id, pds_id, status, response_time, scan_data, scanned_at
        FROM pds_scans
        WHERE pds_id = ?
        ORDER BY scanned_at DESC
        LIMIT ?
    `

	rows, err := s.db.QueryContext(ctx, query, endpointID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []*EndpointScan
	for rows.Next() {
		var scan EndpointScan
		var responseTime sql.NullFloat64
		var scanDataJSON sql.NullString

		err := rows.Scan(&scan.ID, &scan.EndpointID, &scan.Status, &responseTime, &scanDataJSON, &scan.ScannedAt)
		if err != nil {
			return nil, err
		}

		if responseTime.Valid {
			scan.ResponseTime = responseTime.Float64
		}

		if scanDataJSON.Valid && scanDataJSON.String != "" {
			var scanData EndpointScanData
			if err := json.Unmarshal([]byte(scanDataJSON.String), &scanData); err == nil {
				scan.ScanData = &scanData
			}
		}

		scans = append(scans, &scan)
	}

	return scans, rows.Err()
}

// GetEndpointStats returns aggregate statistics about all endpoints
func (s *SQLiteDB) GetEndpointStats(ctx context.Context) (*EndpointStats, error) {
	query := `
        SELECT 
            COUNT(*) as total_endpoints,
            SUM(CASE WHEN status = 1 THEN 1 ELSE 0 END) as online_endpoints,
            SUM(CASE WHEN status = 2 THEN 1 ELSE 0 END) as offline_endpoints,
            (SELECT AVG(response_time) FROM pds_scans WHERE response_time > 0 
             AND scanned_at > datetime('now', '-1 hour')) as avg_response_time,
            SUM(user_count) as total_dids
        FROM endpoints
    `

	var stats EndpointStats
	var avgResponseTime sql.NullFloat64

	err := s.db.QueryRowContext(ctx, query).Scan(
		&stats.TotalEndpoints, &stats.OnlineEndpoints, &stats.OfflineEndpoints,
		&avgResponseTime, &stats.TotalDIDs,
	)

	if avgResponseTime.Valid {
		stats.AvgResponseTime = avgResponseTime.Float64
	}

	// Get counts by type
	typeQuery := `
        SELECT endpoint_type, COUNT(*) 
        FROM endpoints 
        GROUP BY endpoint_type
    `
	rows, err := s.db.QueryContext(ctx, typeQuery)
	if err == nil {
		defer rows.Close()
		stats.ByType = make(map[string]int64)
		for rows.Next() {
			var typ string
			var count int64
			if err := rows.Scan(&typ, &count); err == nil {
				stats.ByType[typ] = count
			}
		}
	}

	return &stats, err
}

// GetScanCursor retrieves cursor with bundle number
func (s *SQLiteDB) GetScanCursor(ctx context.Context, source string) (*ScanCursor, error) {
	query := "SELECT source, last_bundle_number, last_scan_time, records_processed FROM scan_cursors WHERE source = ?"

	var cursor ScanCursor
	err := s.db.QueryRowContext(ctx, query, source).Scan(
		&cursor.Source, &cursor.LastBundleNumber, &cursor.LastScanTime, &cursor.RecordsProcessed,
	)
	if err == sql.ErrNoRows {
		return &ScanCursor{
			Source:           source,
			LastBundleNumber: 0,
			LastScanTime:     time.Time{},
		}, nil
	}
	return &cursor, err
}

// UpdateScanCursor updates cursor with bundle number
func (s *SQLiteDB) UpdateScanCursor(ctx context.Context, cursor *ScanCursor) error {
	query := `
        INSERT INTO scan_cursors (source, last_bundle_number, last_scan_time, records_processed)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(source) DO UPDATE SET
            last_bundle_number = excluded.last_bundle_number,
            last_scan_time = excluded.last_scan_time,
            records_processed = excluded.records_processed
    `
	_, err := s.db.ExecContext(ctx, query, cursor.Source, cursor.LastBundleNumber, cursor.LastScanTime, cursor.RecordsProcessed)
	return err
}

// StorePLCMetrics stores PLC scan metrics
func (s *SQLiteDB) StorePLCMetrics(ctx context.Context, metrics *PLCMetrics) error {
	query := `
        INSERT INTO plc_metrics (total_dids, total_pds, unique_pds, scan_duration_ms, error_count)
        VALUES (?, ?, ?, ?, ?)
    `
	_, err := s.db.ExecContext(ctx, query, metrics.TotalDIDs, metrics.TotalPDS,
		metrics.UniquePDS, metrics.ScanDuration, metrics.ErrorCount)
	return err
}

// GetPLCMetrics retrieves recent PLC metrics
func (s *SQLiteDB) GetPLCMetrics(ctx context.Context, limit int) ([]*PLCMetrics, error) {
	query := `
        SELECT total_dids, total_pds, unique_pds, scan_duration_ms, error_count, created_at
        FROM plc_metrics
        ORDER BY created_at DESC
        LIMIT ?
    `

	rows, err := s.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var metrics []*PLCMetrics
	for rows.Next() {
		var m PLCMetrics
		if err := rows.Scan(&m.TotalDIDs, &m.TotalPDS, &m.UniquePDS, &m.ScanDuration, &m.ErrorCount, &m.LastScanTime); err != nil {
			return nil, err
		}
		metrics = append(metrics, &m)
	}

	return metrics, rows.Err()
}
