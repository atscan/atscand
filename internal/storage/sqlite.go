package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
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
    CREATE TABLE IF NOT EXISTS pds_servers (
        endpoint TEXT PRIMARY KEY,
        discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_checked TIMESTAMP,
        status TEXT DEFAULT 'unknown',
        response_time_ms INTEGER,
        error_message TEXT,
        server_info TEXT,
        dids TEXT DEFAULT '[]',
        user_count INTEGER DEFAULT 0,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_pds_status ON pds_servers(status);
    CREATE INDEX IF NOT EXISTS idx_pds_last_checked ON pds_servers(last_checked);
    CREATE INDEX IF NOT EXISTS idx_pds_user_count ON pds_servers(user_count);

    CREATE TABLE IF NOT EXISTS plc_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        total_dids INTEGER,
        total_pds INTEGER,
        unique_pds INTEGER,
        scan_duration_ms INTEGER,
        error_count INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS pds_scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        endpoint TEXT NOT NULL,
        status TEXT,
        response_time_ms INTEGER,
        error_message TEXT,
        server_info TEXT,
        scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (endpoint) REFERENCES pds_servers(endpoint)
    );

    CREATE INDEX IF NOT EXISTS idx_pds_scans_endpoint ON pds_scans(endpoint);
    CREATE INDEX IF NOT EXISTS idx_pds_scans_scanned_at ON pds_scans(scanned_at);

    CREATE TABLE IF NOT EXISTS scan_cursors (
        source TEXT PRIMARY KEY,
        last_timestamp TEXT NOT NULL,
        last_scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        records_processed INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS plc_bundles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        start_time TIMESTAMP NOT NULL,
        end_time TIMESTAMP NOT NULL,
        operation_count INTEGER NOT NULL,
        dids TEXT NOT NULL,              -- JSON array of DIDs
        file_path TEXT NOT NULL,
        file_size INTEGER NOT NULL,
        compressed BOOLEAN DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    -- CREATE INDEX IF NOT EXISTS idx_plc_bundles_time ON plc_bundles(start_time, end_time);
    -- CREATE INDEX IF NOT EXISTS idx_plc_bundles_created ON plc_bundles(created_at);
    `

	_, err := s.db.Exec(schema)
	return err
}

// CreateBundle stores a new PLC bundle record
func (s *SQLiteDB) CreateBundle(ctx context.Context, bundle *PLCBundle) error {
	didsJSON, err := json.Marshal(bundle.DIDs)
	if err != nil {
		return fmt.Errorf("failed to marshal DIDs: %w", err)
	}

	query := `
        INSERT INTO plc_bundles (start_time, end_time, operation_count, dids, file_path, file_size, compressed)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `
	result, err := s.db.ExecContext(ctx, query,
		bundle.StartTime, bundle.EndTime, bundle.OperationCount,
		string(didsJSON), bundle.FilePath, bundle.FileSize, bundle.Compressed,
	)
	if err != nil {
		return err
	}

	id, _ := result.LastInsertId()
	bundle.ID = id
	return nil
}

// GetBundle retrieves the next bundle after the given timestamp
func (s *SQLiteDB) GetBundle(ctx context.Context, afterTime time.Time) (*PLCBundle, error) {
	var query string
	var args []interface{}

	if afterTime.IsZero() {
		query = `
            SELECT id, start_time, end_time, operation_count, dids, file_path, file_size, compressed, created_at
            FROM plc_bundles
            ORDER BY start_time ASC
            LIMIT 1
        `
		args = []interface{}{}
	} else {
		query = `
            SELECT id, start_time, end_time, operation_count, dids, file_path, file_size, compressed, created_at
            FROM plc_bundles
            WHERE start_time >= ?
            ORDER BY start_time ASC
            LIMIT 1
        `
		args = []interface{}{afterTime}
	}

	var bundle PLCBundle
	var didsJSON string

	err := s.db.QueryRowContext(ctx, query, args...).Scan(
		&bundle.ID, &bundle.StartTime, &bundle.EndTime, &bundle.OperationCount,
		&didsJSON, &bundle.FilePath, &bundle.FileSize, &bundle.Compressed, &bundle.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// Unmarshal DIDs
	if err := json.Unmarshal([]byte(didsJSON), &bundle.DIDs); err != nil {
		return nil, fmt.Errorf("failed to unmarshal DIDs: %w", err)
	}

	return &bundle, nil
}

// GetBundles retrieves recent bundles
func (s *SQLiteDB) GetBundles(ctx context.Context, limit int) ([]*PLCBundle, error) {
	query := `
        SELECT id, start_time, end_time, operation_count, dids, file_path, file_size, compressed, created_at
        FROM plc_bundles
        ORDER BY start_time DESC
        LIMIT ?
    `

	rows, err := s.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return s.scanBundles(rows)
}

// GetAllBundles retrieves all bundles (for DID search)
func (s *SQLiteDB) GetAllBundles(ctx context.Context) ([]*PLCBundle, error) {
	query := `
        SELECT id, start_time, end_time, operation_count, dids, file_path, file_size, compressed, created_at
        FROM plc_bundles
        ORDER BY start_time ASC
    `

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return s.scanBundles(rows)
}

// GetBundlesForDID finds bundles containing a specific DID using JSON functions
func (s *SQLiteDB) GetBundlesForDID(ctx context.Context, did string) ([]*PLCBundle, error) {
	query := `
        SELECT id, start_time, end_time, operation_count, dids, file_path, file_size, compressed, created_at
        FROM plc_bundles
        WHERE EXISTS (
            SELECT 1 FROM json_each(dids) 
            WHERE json_each.value = ?
        )
        ORDER BY start_time ASC
    `

	rows, err := s.db.QueryContext(ctx, query, did)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return s.scanBundles(rows)
}

// GetBundleByID retrieves a single bundle by ID
func (s *SQLiteDB) GetBundleByID(ctx context.Context, bundleID int64) (*PLCBundle, error) {
	query := `
        SELECT id, start_time, end_time, operation_count, dids, file_path, file_size, compressed, created_at
        FROM plc_bundles
        WHERE id = ?
    `

	var bundle PLCBundle
	var didsJSON string

	err := s.db.QueryRowContext(ctx, query, bundleID).Scan(
		&bundle.ID, &bundle.StartTime, &bundle.EndTime, &bundle.OperationCount,
		&didsJSON, &bundle.FilePath, &bundle.FileSize, &bundle.Compressed, &bundle.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal([]byte(didsJSON), &bundle.DIDs); err != nil {
		return nil, fmt.Errorf("failed to unmarshal DIDs: %w", err)
	}

	return &bundle, nil
}

// Helper to scan bundle rows
func (s *SQLiteDB) scanBundles(rows *sql.Rows) ([]*PLCBundle, error) {
	var bundles []*PLCBundle

	for rows.Next() {
		var bundle PLCBundle
		var didsJSON string

		if err := rows.Scan(
			&bundle.ID, &bundle.StartTime, &bundle.EndTime, &bundle.OperationCount,
			&didsJSON, &bundle.FilePath, &bundle.FileSize, &bundle.Compressed, &bundle.CreatedAt,
		); err != nil {
			return nil, err
		}

		// Unmarshal DIDs
		if err := json.Unmarshal([]byte(didsJSON), &bundle.DIDs); err != nil {
			log.Printf("Warning: failed to unmarshal DIDs for bundle %d: %v", bundle.ID, err)
			bundle.DIDs = []string{}
		}

		bundles = append(bundles, &bundle)
	}

	return bundles, rows.Err()
}

// GetBundleStats returns bundle statistics
func (s *SQLiteDB) GetBundleStats(ctx context.Context) (int64, int64, error) {
	query := `
        SELECT COUNT(*), COALESCE(SUM(file_size), 0)
        FROM plc_bundles
    `

	var count, totalSize int64
	err := s.db.QueryRowContext(ctx, query).Scan(&count, &totalSize)
	return count, totalSize, err
}

// PDSExists checks if a PDS endpoint already exists in the database
func (s *SQLiteDB) PDSExists(ctx context.Context, endpoint string) (bool, error) {
	query := "SELECT EXISTS(SELECT 1 FROM pds_servers WHERE endpoint = ?)"

	var exists bool
	err := s.db.QueryRowContext(ctx, query, endpoint).Scan(&exists)
	return exists, err
}

// UpsertPDS inserts or updates a PDS server
func (s *SQLiteDB) UpsertPDS(ctx context.Context, pds *PDS) error {
	query := `
        INSERT INTO pds_servers (endpoint, discovered_at, last_checked, status)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(endpoint) DO UPDATE SET
            last_checked = excluded.last_checked
    `
	_, err := s.db.ExecContext(ctx, query, pds.Endpoint, pds.DiscoveredAt, pds.LastChecked, pds.Status)
	return err
}

// UpdatePDSStatus updates the status, metrics, and DIDs of a PDS server
func (s *SQLiteDB) UpdatePDSStatus(ctx context.Context, endpoint string, update *PDSUpdate) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Marshal server info
	var serverInfoJSON []byte
	if update.ServerInfo != nil {
		serverInfoJSON, _ = json.Marshal(update.ServerInfo)
	}

	// Marshal DIDs
	var didsJSON []byte
	if update.DIDs != nil {
		didsJSON, _ = json.Marshal(update.DIDs)
	} else {
		didsJSON = []byte("[]")
	}

	// Calculate user count
	userCount := len(update.DIDs)

	query := `
        UPDATE pds_servers 
        SET status = ?, last_checked = ?, response_time_ms = ?, error_message = ?, 
            server_info = ?, dids = ?, user_count = ?, updated_at = ?
        WHERE endpoint = ?
    `
	_, err = tx.ExecContext(ctx, query,
		update.Status, update.LastChecked, update.ResponseTime,
		update.ErrorMessage, string(serverInfoJSON), string(didsJSON), userCount, time.Now(), endpoint)
	if err != nil {
		return err
	}

	// Insert scan history
	scanQuery := `
        INSERT INTO pds_scans (endpoint, status, response_time_ms, error_message, server_info)
        VALUES (?, ?, ?, ?, ?)
    `
	_, err = tx.ExecContext(ctx, scanQuery, endpoint, update.Status, update.ResponseTime,
		update.ErrorMessage, string(serverInfoJSON))
	if err != nil {
		return err
	}

	return tx.Commit()
}

// GetPDS retrieves a single PDS server by endpoint
func (s *SQLiteDB) GetPDS(ctx context.Context, endpoint string) (*PDS, error) {
	query := `
        SELECT endpoint, discovered_at, last_checked, status, response_time_ms, 
               error_message, server_info, dids, user_count 
        FROM pds_servers 
        WHERE endpoint = ?
    `

	var pds PDS
	var lastChecked sql.NullTime
	var responseTime sql.NullInt64
	var errorMsg sql.NullString
	var serverInfo sql.NullString
	var didsJSON string

	err := s.db.QueryRowContext(ctx, query, endpoint).Scan(
		&pds.Endpoint, &pds.DiscoveredAt, &lastChecked, &pds.Status,
		&responseTime, &errorMsg, &serverInfo, &didsJSON, &pds.UserCount,
	)
	if err != nil {
		return nil, err
	}

	if lastChecked.Valid {
		pds.LastChecked = lastChecked.Time
	}
	if responseTime.Valid {
		pds.ResponseTime = responseTime.Int64
	}
	if errorMsg.Valid {
		pds.ErrorMessage = errorMsg.String
	}
	if serverInfo.Valid && serverInfo.String != "" {
		json.Unmarshal([]byte(serverInfo.String), &pds.ServerInfo)
	}

	// Unmarshal DIDs
	if didsJSON != "" {
		json.Unmarshal([]byte(didsJSON), &pds.DIDs)
	}

	return &pds, nil
}

// GetPDSServers retrieves multiple PDS servers with optional filtering
func (s *SQLiteDB) GetPDSServers(ctx context.Context, filter *PDSFilter) ([]*PDS, error) {
	query := `
        SELECT endpoint, discovered_at, last_checked, status, response_time_ms, 
               error_message, user_count 
        FROM pds_servers
    `
	args := []interface{}{}

	if filter != nil && filter.Status != "" {
		query += " WHERE status = ?"
		args = append(args, filter.Status)
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

	var servers []*PDS
	for rows.Next() {
		var pds PDS
		var lastChecked sql.NullTime
		var responseTime sql.NullInt64
		var errorMsg sql.NullString

		err := rows.Scan(
			&pds.Endpoint, &pds.DiscoveredAt, &lastChecked, &pds.Status,
			&responseTime, &errorMsg, &pds.UserCount,
		)
		if err != nil {
			return nil, err
		}

		if lastChecked.Valid {
			pds.LastChecked = lastChecked.Time
		}
		if responseTime.Valid {
			pds.ResponseTime = responseTime.Int64
		}
		if errorMsg.Valid {
			pds.ErrorMessage = errorMsg.String
		}

		servers = append(servers, &pds)
	}

	return servers, rows.Err()
}

// GetScanCursor retrieves the last scan cursor for a source
func (s *SQLiteDB) GetScanCursor(ctx context.Context, source string) (*ScanCursor, error) {
	query := "SELECT source, last_timestamp, last_scan_time, records_processed FROM scan_cursors WHERE source = ?"

	var cursor ScanCursor
	err := s.db.QueryRowContext(ctx, query, source).Scan(
		&cursor.Source, &cursor.LastTimestamp, &cursor.LastScanTime, &cursor.RecordsProcessed,
	)
	if err == sql.ErrNoRows {
		// No cursor yet, return empty one
		return &ScanCursor{
			Source:        source,
			LastTimestamp: "",
			LastScanTime:  time.Time{},
		}, nil
	}
	if err != nil {
		return nil, err
	}

	return &cursor, nil
}

// UpdateScanCursor updates or inserts a scan cursor
func (s *SQLiteDB) UpdateScanCursor(ctx context.Context, cursor *ScanCursor) error {
	query := `
        INSERT INTO scan_cursors (source, last_timestamp, last_scan_time, records_processed)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(source) DO UPDATE SET
            last_timestamp = excluded.last_timestamp,
            last_scan_time = excluded.last_scan_time,
            records_processed = excluded.records_processed
    `
	_, err := s.db.ExecContext(ctx, query, cursor.Source, cursor.LastTimestamp, cursor.LastScanTime, cursor.RecordsProcessed)
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

// GetPDSStats returns aggregate statistics about PDS servers
func (s *SQLiteDB) GetPDSStats(ctx context.Context) (*PDSStats, error) {
	query := `
        SELECT 
            COUNT(*) as total_pds,
            SUM(CASE WHEN status = 'online' THEN 1 ELSE 0 END) as online_pds,
            SUM(CASE WHEN status = 'offline' THEN 1 ELSE 0 END) as offline_pds,
            AVG(CASE WHEN response_time_ms > 0 THEN response_time_ms ELSE NULL END) as avg_response_time,
            SUM(user_count) as total_dids
        FROM pds_servers
    `

	var stats PDSStats
	var avgResponseTime sql.NullFloat64

	err := s.db.QueryRowContext(ctx, query).Scan(
		&stats.TotalPDS, &stats.OnlinePDS, &stats.OfflinePDS, &avgResponseTime, &stats.TotalDIDs,
	)

	if avgResponseTime.Valid {
		stats.AvgResponseTime = avgResponseTime.Float64
	}

	return &stats, err
}
