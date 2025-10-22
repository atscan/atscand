package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

type PostgresDB struct {
	db *sql.DB
}

func NewPostgresDB(connString string) (*PostgresDB, error) {
	db, err := sql.Open("postgres", connString)
	if err != nil {
		return nil, err
	}

	// Connection pool settings
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(2 * time.Minute)

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &PostgresDB{db: db}, nil
}

func (p *PostgresDB) Close() error {
	return p.db.Close()
}

func (p *PostgresDB) Migrate() error {
	schema := `
    -- Endpoints table
    CREATE TABLE IF NOT EXISTS endpoints (
        id BIGSERIAL PRIMARY KEY,
        endpoint_type TEXT NOT NULL DEFAULT 'pds',
        endpoint TEXT NOT NULL,
        discovered_at TIMESTAMP NOT NULL,
        last_checked TIMESTAMP,
        status INTEGER DEFAULT 0,
        user_count BIGINT DEFAULT 0,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(endpoint_type, endpoint)
    );

    CREATE INDEX IF NOT EXISTS idx_endpoints_type_endpoint ON endpoints(endpoint_type, endpoint);
    CREATE INDEX IF NOT EXISTS idx_endpoints_status ON endpoints(status);
    CREATE INDEX IF NOT EXISTS idx_endpoints_type ON endpoints(endpoint_type);
    CREATE INDEX IF NOT EXISTS idx_endpoints_user_count ON endpoints(user_count);

    CREATE TABLE IF NOT EXISTS pds_scans (
        id BIGSERIAL PRIMARY KEY,
        pds_id BIGINT NOT NULL,
        status INTEGER NOT NULL,
        response_time DOUBLE PRECISION,
        scan_data JSONB,
        scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (pds_id) REFERENCES endpoints(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_pds_scans_pds_id ON pds_scans(pds_id);
    CREATE INDEX IF NOT EXISTS idx_pds_scans_scanned_at ON pds_scans(scanned_at);
    CREATE INDEX IF NOT EXISTS idx_pds_scans_scan_data ON pds_scans USING gin(scan_data);

    CREATE TABLE IF NOT EXISTS plc_metrics (
        id BIGSERIAL PRIMARY KEY,
        total_dids BIGINT,
        total_pds BIGINT,
        unique_pds BIGINT,
        scan_duration_ms BIGINT,
        error_count INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS scan_cursors (
        source TEXT PRIMARY KEY,
        last_bundle_number INTEGER DEFAULT 0,
        last_scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        records_processed BIGINT DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS plc_bundles (
        bundle_number INTEGER PRIMARY KEY,
        start_time TIMESTAMP NOT NULL,
        end_time TIMESTAMP NOT NULL,
        dids JSONB NOT NULL,
        hash TEXT NOT NULL,
        compressed_hash TEXT NOT NULL,
        compressed_size BIGINT NOT NULL,
        uncompressed_size BIGINT NOT NULL,
        cumulative_compressed_size BIGINT NOT NULL,
        cumulative_uncompressed_size BIGINT NOT NULL,
        cursor TEXT,
        prev_bundle_hash TEXT,
        compressed BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_plc_bundles_time ON plc_bundles(start_time, end_time);
    CREATE INDEX IF NOT EXISTS idx_plc_bundles_hash ON plc_bundles(hash);
    CREATE INDEX IF NOT EXISTS idx_plc_bundles_prev ON plc_bundles(prev_bundle_hash);
    CREATE INDEX IF NOT EXISTS idx_plc_bundles_number_desc ON plc_bundles(bundle_number DESC);
    CREATE INDEX IF NOT EXISTS idx_plc_bundles_dids ON plc_bundles USING gin(dids);

    CREATE TABLE IF NOT EXISTS plc_mempool (
        id BIGSERIAL PRIMARY KEY,
        did TEXT NOT NULL,
        operation TEXT NOT NULL,
        cid TEXT NOT NULL UNIQUE,
        created_at TIMESTAMP NOT NULL,
        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_mempool_created_at ON plc_mempool(created_at);
    CREATE INDEX IF NOT EXISTS idx_mempool_did ON plc_mempool(did);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_mempool_cid ON plc_mempool(cid);

    CREATE TABLE IF NOT EXISTS dids (
        did TEXT PRIMARY KEY,
        first_seen_bundle INTEGER NOT NULL,
        last_seen_bundle INTEGER NOT NULL,
        bundle_numbers JSONB NOT NULL,
        operation_count INTEGER DEFAULT 1,
        first_seen_at TIMESTAMP NOT NULL,
        last_seen_at TIMESTAMP NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_dids_did ON dids(did);
    CREATE INDEX IF NOT EXISTS idx_dids_last_bundle ON dids(last_seen_bundle);
    CREATE INDEX IF NOT EXISTS idx_dids_first_seen ON dids(first_seen_at);
    CREATE INDEX IF NOT EXISTS idx_dids_last_seen ON dids(last_seen_at);
    CREATE INDEX IF NOT EXISTS idx_dids_bundle_numbers ON dids USING gin(bundle_numbers);
    `

	_, err := p.db.Exec(schema)
	return err
}

// ===== BUNDLE OPERATIONS =====

func (p *PostgresDB) CreateBundle(ctx context.Context, bundle *PLCBundle) error {
	didsJSON, err := json.Marshal(bundle.DIDs)
	if err != nil {
		return err
	}

	// Calculate cumulative sizes from previous bundle
	if bundle.BundleNumber > 1 {
		prevBundle, err := p.GetBundleByNumber(ctx, bundle.BundleNumber-1)
		if err == nil && prevBundle != nil {
			bundle.CumulativeCompressedSize = prevBundle.CumulativeCompressedSize + bundle.CompressedSize
			bundle.CumulativeUncompressedSize = prevBundle.CumulativeUncompressedSize + bundle.UncompressedSize
		} else {
			bundle.CumulativeCompressedSize = bundle.CompressedSize
			bundle.CumulativeUncompressedSize = bundle.UncompressedSize
		}
	} else {
		bundle.CumulativeCompressedSize = bundle.CompressedSize
		bundle.CumulativeUncompressedSize = bundle.UncompressedSize
	}

	query := `
        INSERT INTO plc_bundles (
            bundle_number, start_time, end_time, dids, 
            hash, compressed_hash, compressed_size, uncompressed_size, 
            cumulative_compressed_size, cumulative_uncompressed_size,
            cursor, prev_bundle_hash, compressed
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        ON CONFLICT(bundle_number) DO UPDATE SET
            start_time = EXCLUDED.start_time,
            end_time = EXCLUDED.end_time,
            dids = EXCLUDED.dids,
            hash = EXCLUDED.hash,
            compressed_hash = EXCLUDED.compressed_hash,
            compressed_size = EXCLUDED.compressed_size,
            uncompressed_size = EXCLUDED.uncompressed_size,
            cumulative_compressed_size = EXCLUDED.cumulative_compressed_size,
            cumulative_uncompressed_size = EXCLUDED.cumulative_uncompressed_size,
            cursor = EXCLUDED.cursor,
            prev_bundle_hash = EXCLUDED.prev_bundle_hash,
            compressed = EXCLUDED.compressed
    `
	_, err = p.db.ExecContext(ctx, query,
		bundle.BundleNumber, bundle.StartTime, bundle.EndTime,
		didsJSON, bundle.Hash, bundle.CompressedHash,
		bundle.CompressedSize, bundle.UncompressedSize,
		bundle.CumulativeCompressedSize, bundle.CumulativeUncompressedSize,
		bundle.Cursor, bundle.PrevBundleHash, bundle.Compressed,
	)

	return err
}

func (p *PostgresDB) GetBundleByNumber(ctx context.Context, bundleNumber int) (*PLCBundle, error) {
	query := `
        SELECT bundle_number, start_time, end_time, dids, hash, compressed_hash, 
               compressed_size, uncompressed_size, cumulative_compressed_size, 
               cumulative_uncompressed_size, cursor, prev_bundle_hash, compressed, created_at
        FROM plc_bundles
        WHERE bundle_number = $1
    `

	var bundle PLCBundle
	var didsJSON []byte
	var prevHash sql.NullString
	var cursor sql.NullString

	err := p.db.QueryRowContext(ctx, query, bundleNumber).Scan(
		&bundle.BundleNumber, &bundle.StartTime, &bundle.EndTime,
		&didsJSON, &bundle.Hash, &bundle.CompressedHash,
		&bundle.CompressedSize, &bundle.UncompressedSize,
		&bundle.CumulativeCompressedSize, &bundle.CumulativeUncompressedSize,
		&cursor, &prevHash, &bundle.Compressed, &bundle.CreatedAt,
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

	json.Unmarshal(didsJSON, &bundle.DIDs)
	return &bundle, nil
}

func (p *PostgresDB) GetBundles(ctx context.Context, limit int) ([]*PLCBundle, error) {
	query := `
        SELECT bundle_number, start_time, end_time, dids, hash, compressed_hash, 
               compressed_size, uncompressed_size, cumulative_compressed_size, 
               cumulative_uncompressed_size, cursor, prev_bundle_hash, compressed, created_at
        FROM plc_bundles
        ORDER BY bundle_number DESC
        LIMIT $1
    `

	rows, err := p.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return p.scanBundles(rows)
}

func (p *PostgresDB) GetBundlesForDID(ctx context.Context, did string) ([]*PLCBundle, error) {
	query := `
        SELECT bundle_number, start_time, end_time, dids, hash, compressed_hash, 
               compressed_size, uncompressed_size, cumulative_compressed_size, 
               cumulative_uncompressed_size, cursor, prev_bundle_hash, compressed, created_at
        FROM plc_bundles
        WHERE dids ? $1
        ORDER BY bundle_number ASC
    `

	rows, err := p.db.QueryContext(ctx, query, did)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return p.scanBundles(rows)
}

func (p *PostgresDB) scanBundles(rows *sql.Rows) ([]*PLCBundle, error) {
	var bundles []*PLCBundle

	for rows.Next() {
		var bundle PLCBundle
		var didsJSON []byte
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
			&bundle.CumulativeCompressedSize,
			&bundle.CumulativeUncompressedSize,
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

		json.Unmarshal(didsJSON, &bundle.DIDs)
		bundles = append(bundles, &bundle)
	}

	return bundles, rows.Err()
}

func (p *PostgresDB) GetBundleStats(ctx context.Context) (int64, int64, int64, int64, error) {
	var count, lastBundleNum int64
	err := p.db.QueryRowContext(ctx, `
		SELECT COUNT(*), COALESCE(MAX(bundle_number), 0) 
		FROM plc_bundles
	`).Scan(&count, &lastBundleNum)
	if err != nil {
		return 0, 0, 0, 0, err
	}

	if lastBundleNum == 0 {
		return 0, 0, 0, 0, nil
	}

	var compressedSize, uncompressedSize int64
	err = p.db.QueryRowContext(ctx, `
		SELECT cumulative_compressed_size, cumulative_uncompressed_size
		FROM plc_bundles
		WHERE bundle_number = $1
	`, lastBundleNum).Scan(&compressedSize, &uncompressedSize)
	if err != nil {
		return 0, 0, 0, 0, err
	}

	return count, compressedSize, uncompressedSize, lastBundleNum, nil
}

func (p *PostgresDB) GetLastBundleNumber(ctx context.Context) (int, error) {
	query := "SELECT COALESCE(MAX(bundle_number), 0) FROM plc_bundles"
	var num int
	err := p.db.QueryRowContext(ctx, query).Scan(&num)
	return num, err
}

func (p *PostgresDB) GetBundleForTimestamp(ctx context.Context, afterTime time.Time) (int, error) {
	query := `
		SELECT bundle_number 
		FROM plc_bundles 
		WHERE start_time <= $1 AND end_time >= $1
		ORDER BY bundle_number ASC 
		LIMIT 1
	`

	var bundleNum int
	err := p.db.QueryRowContext(ctx, query, afterTime).Scan(&bundleNum)
	if err == sql.ErrNoRows {
		query = `
			SELECT bundle_number 
			FROM plc_bundles 
			WHERE end_time < $1
			ORDER BY bundle_number DESC 
			LIMIT 1
		`
		err = p.db.QueryRowContext(ctx, query, afterTime).Scan(&bundleNum)
		if err == sql.ErrNoRows {
			return 1, nil
		}
		if err != nil {
			return 0, err
		}
		return bundleNum, nil
	}
	if err != nil {
		return 0, err
	}

	return bundleNum, nil
}

// ===== MEMPOOL OPERATIONS =====

func (p *PostgresDB) AddToMempool(ctx context.Context, ops []MempoolOperation) error {
	if len(ops) == 0 {
		return nil
	}

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
        INSERT INTO plc_mempool (did, operation, cid, created_at) 
        VALUES ($1, $2, $3, $4)
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

func (p *PostgresDB) GetMempoolCount(ctx context.Context) (int, error) {
	query := "SELECT COUNT(*) FROM plc_mempool"
	var count int
	err := p.db.QueryRowContext(ctx, query).Scan(&count)
	return count, err
}

func (p *PostgresDB) GetMempoolOperations(ctx context.Context, limit int) ([]MempoolOperation, error) {
	query := `
        SELECT id, did, operation, cid, created_at, added_at
        FROM plc_mempool
        ORDER BY created_at ASC
        LIMIT $1
    `

	rows, err := p.db.QueryContext(ctx, query, limit)
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

func (p *PostgresDB) DeleteFromMempool(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}

	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}

	query := fmt.Sprintf("DELETE FROM plc_mempool WHERE id IN (%s)",
		strings.Join(placeholders, ","))

	_, err := p.db.ExecContext(ctx, query, args...)
	return err
}

func (p *PostgresDB) GetFirstMempoolOperation(ctx context.Context) (*MempoolOperation, error) {
	query := `
        SELECT id, did, operation, cid, created_at, added_at
        FROM plc_mempool
        ORDER BY created_at ASC, id ASC
        LIMIT 1
    `

	var op MempoolOperation
	err := p.db.QueryRowContext(ctx, query).Scan(
		&op.ID, &op.DID, &op.Operation, &op.CID, &op.CreatedAt, &op.AddedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &op, nil
}

func (p *PostgresDB) GetLastMempoolOperation(ctx context.Context) (*MempoolOperation, error) {
	query := `
        SELECT id, did, operation, cid, created_at, added_at
        FROM plc_mempool
        ORDER BY created_at DESC, id DESC
        LIMIT 1
    `

	var op MempoolOperation
	err := p.db.QueryRowContext(ctx, query).Scan(
		&op.ID, &op.DID, &op.Operation, &op.CID, &op.CreatedAt, &op.AddedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &op, nil
}

func (p *PostgresDB) GetMempoolUniqueDIDCount(ctx context.Context) (int, error) {
	query := "SELECT COUNT(DISTINCT did) FROM plc_mempool"
	var count int
	err := p.db.QueryRowContext(ctx, query).Scan(&count)
	return count, err
}

func (p *PostgresDB) GetMempoolUncompressedSize(ctx context.Context) (int64, error) {
	query := "SELECT COALESCE(SUM(LENGTH(operation)), 0) FROM plc_mempool"
	var size int64
	err := p.db.QueryRowContext(ctx, query).Scan(&size)
	return size, err
}

// ===== ENDPOINT OPERATIONS =====

func (p *PostgresDB) UpsertEndpoint(ctx context.Context, endpoint *Endpoint) error {
	query := `
        INSERT INTO endpoints (endpoint_type, endpoint, discovered_at, last_checked, status)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT(endpoint_type, endpoint) DO UPDATE SET
            last_checked = EXCLUDED.last_checked
        RETURNING id
    `
	err := p.db.QueryRowContext(ctx, query,
		endpoint.EndpointType, endpoint.Endpoint, endpoint.DiscoveredAt,
		endpoint.LastChecked, endpoint.Status).Scan(&endpoint.ID)
	return err
}

func (p *PostgresDB) EndpointExists(ctx context.Context, endpoint string, endpointType string) (bool, error) {
	query := "SELECT EXISTS(SELECT 1 FROM endpoints WHERE endpoint = $1 AND endpoint_type = $2)"
	var exists bool
	err := p.db.QueryRowContext(ctx, query, endpoint, endpointType).Scan(&exists)
	return exists, err
}

func (p *PostgresDB) GetEndpointIDByEndpoint(ctx context.Context, endpoint string, endpointType string) (int64, error) {
	query := "SELECT id FROM endpoints WHERE endpoint = $1 AND endpoint_type = $2"
	var id int64
	err := p.db.QueryRowContext(ctx, query, endpoint, endpointType).Scan(&id)
	return id, err
}

func (p *PostgresDB) GetEndpoint(ctx context.Context, endpoint string, endpointType string) (*Endpoint, error) {
	query := `
        SELECT id, endpoint_type, endpoint, discovered_at, last_checked, status, user_count, updated_at
        FROM endpoints 
        WHERE endpoint = $1 AND endpoint_type = $2
    `

	var ep Endpoint
	var lastChecked sql.NullTime

	err := p.db.QueryRowContext(ctx, query, endpoint, endpointType).Scan(
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

func (p *PostgresDB) GetEndpointByID(ctx context.Context, id int64) (*Endpoint, error) {
	query := `
        SELECT id, endpoint_type, endpoint, discovered_at, last_checked, status, user_count, updated_at
        FROM endpoints 
        WHERE id = $1
    `

	var ep Endpoint
	var lastChecked sql.NullTime

	err := p.db.QueryRowContext(ctx, query, id).Scan(
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

func (p *PostgresDB) GetEndpoints(ctx context.Context, filter *EndpointFilter) ([]*Endpoint, error) {
	query := `
        SELECT id, endpoint_type, endpoint, discovered_at, last_checked, status, user_count, updated_at
        FROM endpoints
        WHERE 1=1
    `
	args := []interface{}{}
	argIdx := 1

	if filter != nil {
		if filter.Type != "" {
			query += fmt.Sprintf(" AND endpoint_type = $%d", argIdx)
			args = append(args, filter.Type)
			argIdx++
		}
		if filter.Status != "" {
			statusInt := EndpointStatusUnknown
			switch filter.Status {
			case "online":
				statusInt = EndpointStatusOnline
			case "offline":
				statusInt = EndpointStatusOffline
			}
			query += fmt.Sprintf(" AND status = $%d", argIdx)
			args = append(args, statusInt)
			argIdx++
		}
		if filter.MinUserCount > 0 {
			query += fmt.Sprintf(" AND user_count >= $%d", argIdx)
			args = append(args, filter.MinUserCount)
			argIdx++
		}
	}

	query += " ORDER BY user_count DESC"

	if filter != nil && filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
		args = append(args, filter.Limit, filter.Offset)
	}

	rows, err := p.db.QueryContext(ctx, query, args...)
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

func (p *PostgresDB) UpdateEndpointStatus(ctx context.Context, endpointID int64, update *EndpointUpdate) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	userCount := 0
	if update.ScanData != nil {
		userCount = update.ScanData.DIDCount
	}

	query := `
        UPDATE endpoints 
        SET status = $1, last_checked = $2, user_count = $3, updated_at = $4
        WHERE id = $5
    `
	_, err = tx.ExecContext(ctx, query, update.Status, update.LastChecked, userCount, time.Now(), endpointID)
	if err != nil {
		return err
	}

	var scanDataJSON []byte
	if update.ScanData != nil {
		scanDataJSON, _ = json.Marshal(update.ScanData)
	}

	scanQuery := `
        INSERT INTO pds_scans (pds_id, status, response_time, scan_data)
        VALUES ($1, $2, $3, $4)
    `
	_, err = tx.ExecContext(ctx, scanQuery, endpointID, update.Status, update.ResponseTime, scanDataJSON)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (p *PostgresDB) GetEndpointScans(ctx context.Context, endpointID int64, limit int) ([]*EndpointScan, error) {
	query := `
        SELECT id, pds_id, status, response_time, scan_data, scanned_at
        FROM pds_scans
        WHERE pds_id = $1
        ORDER BY scanned_at DESC
        LIMIT $2
    `

	rows, err := p.db.QueryContext(ctx, query, endpointID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []*EndpointScan
	for rows.Next() {
		var scan EndpointScan
		var responseTime sql.NullFloat64
		var scanDataJSON []byte

		err := rows.Scan(&scan.ID, &scan.EndpointID, &scan.Status, &responseTime, &scanDataJSON, &scan.ScannedAt)
		if err != nil {
			return nil, err
		}

		if responseTime.Valid {
			scan.ResponseTime = responseTime.Float64
		}

		if len(scanDataJSON) > 0 {
			var scanData EndpointScanData
			if err := json.Unmarshal(scanDataJSON, &scanData); err == nil {
				scan.ScanData = &scanData
			}
		}

		scans = append(scans, &scan)
	}

	return scans, rows.Err()
}

func (p *PostgresDB) GetEndpointStats(ctx context.Context) (*EndpointStats, error) {
	query := `
        SELECT 
            COUNT(*) as total_endpoints,
            SUM(CASE WHEN status = 1 THEN 1 ELSE 0 END) as online_endpoints,
            SUM(CASE WHEN status = 2 THEN 1 ELSE 0 END) as offline_endpoints,
            (SELECT AVG(response_time) FROM pds_scans WHERE response_time > 0 
             AND scanned_at > NOW() - INTERVAL '1 hour') as avg_response_time,
            SUM(user_count) as total_dids
        FROM endpoints
    `

	var stats EndpointStats
	var avgResponseTime sql.NullFloat64

	err := p.db.QueryRowContext(ctx, query).Scan(
		&stats.TotalEndpoints, &stats.OnlineEndpoints, &stats.OfflineEndpoints,
		&avgResponseTime, &stats.TotalDIDs,
	)

	if avgResponseTime.Valid {
		stats.AvgResponseTime = avgResponseTime.Float64
	}

	typeQuery := `
        SELECT endpoint_type, COUNT(*) 
        FROM endpoints 
        GROUP BY endpoint_type
    `
	rows, err := p.db.QueryContext(ctx, typeQuery)
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

// ===== CURSOR OPERATIONS =====

func (p *PostgresDB) GetScanCursor(ctx context.Context, source string) (*ScanCursor, error) {
	query := "SELECT source, last_bundle_number, last_scan_time, records_processed FROM scan_cursors WHERE source = $1"

	var cursor ScanCursor
	err := p.db.QueryRowContext(ctx, query, source).Scan(
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

func (p *PostgresDB) UpdateScanCursor(ctx context.Context, cursor *ScanCursor) error {
	query := `
        INSERT INTO scan_cursors (source, last_bundle_number, last_scan_time, records_processed)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT(source) DO UPDATE SET
            last_bundle_number = EXCLUDED.last_bundle_number,
            last_scan_time = EXCLUDED.last_scan_time,
            records_processed = EXCLUDED.records_processed
    `
	_, err := p.db.ExecContext(ctx, query, cursor.Source, cursor.LastBundleNumber, cursor.LastScanTime, cursor.RecordsProcessed)
	return err
}

// ===== METRICS OPERATIONS =====

func (p *PostgresDB) StorePLCMetrics(ctx context.Context, metrics *PLCMetrics) error {
	query := `
        INSERT INTO plc_metrics (total_dids, total_pds, unique_pds, scan_duration_ms, error_count)
        VALUES ($1, $2, $3, $4, $5)
    `
	_, err := p.db.ExecContext(ctx, query, metrics.TotalDIDs, metrics.TotalPDS,
		metrics.UniquePDS, metrics.ScanDuration, metrics.ErrorCount)
	return err
}

func (p *PostgresDB) GetPLCMetrics(ctx context.Context, limit int) ([]*PLCMetrics, error) {
	query := `
        SELECT total_dids, total_pds, unique_pds, scan_duration_ms, error_count, created_at
        FROM plc_metrics
        ORDER BY created_at DESC
        LIMIT $1
    `

	rows, err := p.db.QueryContext(ctx, query, limit)
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

// ===== DID OPERATIONS =====

func (p *PostgresDB) UpsertDID(ctx context.Context, did *DIDRecord) error {
	bundleNumbersJSON, err := json.Marshal(did.BundleNumbers)
	if err != nil {
		return err
	}

	query := `
        INSERT INTO dids (did, first_seen_bundle, last_seen_bundle, bundle_numbers, operation_count, first_seen_at, last_seen_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT(did) DO UPDATE SET
            last_seen_bundle = EXCLUDED.last_seen_bundle,
            bundle_numbers = EXCLUDED.bundle_numbers,
            operation_count = EXCLUDED.operation_count,
            last_seen_at = EXCLUDED.last_seen_at
    `
	_, err = p.db.ExecContext(ctx, query,
		did.DID, did.FirstSeenBundle, did.LastSeenBundle,
		bundleNumbersJSON, did.OperationCount,
		did.FirstSeenAt, did.LastSeenAt)
	return err
}

func (p *PostgresDB) GetDIDRecord(ctx context.Context, did string) (*DIDRecord, error) {
	query := `
        SELECT did, first_seen_bundle, last_seen_bundle, bundle_numbers, operation_count, first_seen_at, last_seen_at
        FROM dids
        WHERE did = $1
    `

	var record DIDRecord
	var bundleNumbersJSON []byte

	err := p.db.QueryRowContext(ctx, query, did).Scan(
		&record.DID, &record.FirstSeenBundle, &record.LastSeenBundle,
		&bundleNumbersJSON, &record.OperationCount,
		&record.FirstSeenAt, &record.LastSeenAt,
	)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(bundleNumbersJSON, &record.BundleNumbers); err != nil {
		return nil, err
	}

	return &record, nil
}

func (p *PostgresDB) AddBundleDIDs(ctx context.Context, bundleNum int, dids []string, firstSeenAt, lastSeenAt time.Time) error {
	if len(dids) == 0 {
		return nil
	}

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Get existing DIDs
	existingDIDs := make(map[string][]int)
	if len(dids) > 0 {
		placeholders := make([]string, len(dids))
		args := make([]interface{}, len(dids))
		for i, did := range dids {
			placeholders[i] = fmt.Sprintf("$%d", i+1)
			args[i] = did
		}

		query := fmt.Sprintf(`
			SELECT did, bundle_numbers
			FROM dids
			WHERE did IN (%s)
		`, strings.Join(placeholders, ","))

		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return err
		}

		for rows.Next() {
			var did string
			var bundleNumbersJSON []byte
			if err := rows.Scan(&did, &bundleNumbersJSON); err != nil {
				rows.Close()
				return err
			}

			var bundles []int
			if err := json.Unmarshal(bundleNumbersJSON, &bundles); err != nil {
				rows.Close()
				return err
			}

			existingDIDs[did] = bundles
		}
		rows.Close()

		if err := rows.Err(); err != nil {
			return err
		}
	}

	// Batch upsert
	batchSize := 500
	for i := 0; i < len(dids); i += batchSize {
		end := i + batchSize
		if end > len(dids) {
			end = len(dids)
		}
		batch := dids[i:end]

		if err := p.bulkUpsertDIDsSimplified(ctx, tx, bundleNum, batch, existingDIDs, firstSeenAt, lastSeenAt); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (p *PostgresDB) bulkUpsertDIDsSimplified(ctx context.Context, tx *sql.Tx, bundleNum int, dids []string, existingDIDs map[string][]int, firstSeenAt, lastSeenAt time.Time) error {
	if len(dids) == 0 {
		return nil
	}

	var values []string
	var args []interface{}
	argIdx := 1

	for _, did := range dids {
		bundles := existingDIDs[did]

		alreadyHas := false
		for _, b := range bundles {
			if b == bundleNum {
				alreadyHas = true
				break
			}
		}

		if !alreadyHas {
			bundles = append(bundles, bundleNum)
		}

		bundleNumbersJSON, _ := json.Marshal(bundles)

		if len(existingDIDs[did]) > 0 {
			values = append(values, fmt.Sprintf("($%d, $%d, $%d, $%d, $%d, $%d, $%d)",
				argIdx, argIdx+1, argIdx+2, argIdx+3, argIdx+4, argIdx+5, argIdx+6))
			args = append(args, did, bundleNum, bundleNum, bundleNumbersJSON, len(bundles), firstSeenAt, lastSeenAt)
			argIdx += 7
		} else {
			values = append(values, fmt.Sprintf("($%d, $%d, $%d, $%d, 1, $%d, $%d)",
				argIdx, argIdx+1, argIdx+2, argIdx+3, argIdx+4, argIdx+5))
			args = append(args, did, bundleNum, bundleNum, bundleNumbersJSON, firstSeenAt, lastSeenAt)
			argIdx += 6
		}
	}

	query := fmt.Sprintf(`
		INSERT INTO dids (did, first_seen_bundle, last_seen_bundle, bundle_numbers, operation_count, first_seen_at, last_seen_at)
		VALUES %s
		ON CONFLICT(did) DO UPDATE SET
			last_seen_bundle = EXCLUDED.last_seen_bundle,
			bundle_numbers = EXCLUDED.bundle_numbers,
			operation_count = EXCLUDED.operation_count,
			last_seen_at = EXCLUDED.last_seen_at
	`, strings.Join(values, ","))

	_, err := tx.ExecContext(ctx, query, args...)
	return err
}

func (p *PostgresDB) GetTotalDIDCount(ctx context.Context) (int64, error) {
	query := "SELECT COUNT(*) FROM dids"
	var count int64
	err := p.db.QueryRowContext(ctx, query).Scan(&count)
	return count, err
}
