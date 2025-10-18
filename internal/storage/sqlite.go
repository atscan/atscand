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
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        endpoint TEXT UNIQUE NOT NULL,
        discovered_at TIMESTAMP NOT NULL,
        last_checked TIMESTAMP,
        status INTEGER DEFAULT 0,  -- 0=unknown, 1=online, 2=offline
        user_count INTEGER DEFAULT 0,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_pds_endpoint ON pds_servers(endpoint);
    CREATE INDEX IF NOT EXISTS idx_pds_status ON pds_servers(status);
    CREATE INDEX IF NOT EXISTS idx_pds_user_count ON pds_servers(user_count);

    CREATE TABLE IF NOT EXISTS pds_scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pds_id INTEGER NOT NULL,
        status INTEGER NOT NULL,
        response_time REAL,  -- milliseconds as float
        scan_data TEXT,  -- JSON: {server_info, dids, did_count}
        scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (pds_id) REFERENCES pds_servers(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_pds_scans_pds_id ON pds_scans(pds_id);
    CREATE INDEX IF NOT EXISTS idx_pds_scans_scanned_at ON pds_scans(scanned_at);

    CREATE TABLE IF NOT EXISTS plc_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        total_dids INTEGER,
        total_pds INTEGER,
        unique_pds INTEGER,
        scan_duration_ms INTEGER,
        error_count INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

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
        dids TEXT NOT NULL,
        file_path TEXT NOT NULL,
        file_size INTEGER NOT NULL,
        compressed BOOLEAN DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_plc_bundles_time ON plc_bundles(start_time, end_time);
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

// UpsertPDS inserts or updates a PDS server
func (s *SQLiteDB) UpsertPDS(ctx context.Context, pds *PDS) error {
	query := `
        INSERT INTO pds_servers (endpoint, discovered_at, last_checked, status)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(endpoint) DO UPDATE SET
            last_checked = excluded.last_checked
        RETURNING id
    `
	err := s.db.QueryRowContext(ctx, query, pds.Endpoint, pds.DiscoveredAt, pds.LastChecked, pds.Status).Scan(&pds.ID)
	return err
}

// PDSExists checks if a PDS endpoint already exists
func (s *SQLiteDB) PDSExists(ctx context.Context, endpoint string) (bool, error) {
	query := "SELECT EXISTS(SELECT 1 FROM pds_servers WHERE endpoint = ?)"
	var exists bool
	err := s.db.QueryRowContext(ctx, query, endpoint).Scan(&exists)
	return exists, err
}

// GetPDSIDByEndpoint gets the ID for an endpoint
func (s *SQLiteDB) GetPDSIDByEndpoint(ctx context.Context, endpoint string) (int64, error) {
	query := "SELECT id FROM pds_servers WHERE endpoint = ?"
	var id int64
	err := s.db.QueryRowContext(ctx, query, endpoint).Scan(&id)
	return id, err
}

// GetPDS retrieves a PDS by endpoint
func (s *SQLiteDB) GetPDS(ctx context.Context, endpoint string) (*PDS, error) {
	query := `
        SELECT id, endpoint, discovered_at, last_checked, status, user_count, updated_at
        FROM pds_servers 
        WHERE endpoint = ?
    `

	var pds PDS
	var lastChecked sql.NullTime

	err := s.db.QueryRowContext(ctx, query, endpoint).Scan(
		&pds.ID, &pds.Endpoint, &pds.DiscoveredAt, &lastChecked,
		&pds.Status, &pds.UserCount, &pds.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	if lastChecked.Valid {
		pds.LastChecked = lastChecked.Time
	}

	return &pds, nil
}

// GetPDSByID retrieves a PDS by ID
func (s *SQLiteDB) GetPDSByID(ctx context.Context, id int64) (*PDS, error) {
	query := `
        SELECT id, endpoint, discovered_at, last_checked, status, user_count, updated_at
        FROM pds_servers 
        WHERE id = ?
    `

	var pds PDS
	var lastChecked sql.NullTime

	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&pds.ID, &pds.Endpoint, &pds.DiscoveredAt, &lastChecked,
		&pds.Status, &pds.UserCount, &pds.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	if lastChecked.Valid {
		pds.LastChecked = lastChecked.Time
	}

	return &pds, nil
}

// GetPDSServers retrieves multiple PDS servers
func (s *SQLiteDB) GetPDSServers(ctx context.Context, filter *PDSFilter) ([]*PDS, error) {
	query := `
        SELECT id, endpoint, discovered_at, last_checked, status, user_count, updated_at
        FROM pds_servers
    `
	args := []interface{}{}

	if filter != nil && filter.Status != "" {
		// Map string status to int
		statusInt := PDSStatusUnknown
		switch filter.Status {
		case "online":
			statusInt = PDSStatusOnline
		case "offline":
			statusInt = PDSStatusOffline
		}
		query += " WHERE status = ?"
		args = append(args, statusInt)
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

		err := rows.Scan(
			&pds.ID, &pds.Endpoint, &pds.DiscoveredAt, &lastChecked,
			&pds.Status, &pds.UserCount, &pds.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		if lastChecked.Valid {
			pds.LastChecked = lastChecked.Time
		}

		servers = append(servers, &pds)
	}

	return servers, rows.Err()
}

// UpdatePDSStatus updates the status and creates a scan record
func (s *SQLiteDB) UpdatePDSStatus(ctx context.Context, pdsID int64, update *PDSUpdate) error {
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

	// Update main pds_servers record
	query := `
        UPDATE pds_servers 
        SET status = ?, last_checked = ?, user_count = ?, updated_at = ?
        WHERE id = ?
    `
	_, err = tx.ExecContext(ctx, query, update.Status, update.LastChecked, userCount, time.Now(), pdsID)
	if err != nil {
		return err
	}

	// Marshal scan data
	var scanDataJSON []byte
	if update.ScanData != nil {
		scanDataJSON, _ = json.Marshal(update.ScanData)
	}

	// Insert scan history
	scanQuery := `
        INSERT INTO pds_scans (pds_id, status, response_time, scan_data)
        VALUES (?, ?, ?, ?)
    `
	_, err = tx.ExecContext(ctx, scanQuery, pdsID, update.Status, update.ResponseTime, string(scanDataJSON))
	if err != nil {
		return err
	}

	return tx.Commit()
}

// GetPDSScans retrieves scan history for a PDS
func (s *SQLiteDB) GetPDSScans(ctx context.Context, pdsID int64, limit int) ([]*PDSScan, error) {
	query := `
        SELECT id, pds_id, status, response_time, scan_data, scanned_at
        FROM pds_scans
        WHERE pds_id = ?
        ORDER BY scanned_at DESC
        LIMIT ?
    `

	rows, err := s.db.QueryContext(ctx, query, pdsID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []*PDSScan
	for rows.Next() {
		var scan PDSScan
		var responseTime sql.NullFloat64
		var scanDataJSON sql.NullString

		err := rows.Scan(&scan.ID, &scan.PDSID, &scan.Status, &responseTime, &scanDataJSON, &scan.ScannedAt)
		if err != nil {
			return nil, err
		}

		if responseTime.Valid {
			scan.ResponseTime = responseTime.Float64
		}

		if scanDataJSON.Valid && scanDataJSON.String != "" {
			var scanData PDSScanData
			if err := json.Unmarshal([]byte(scanDataJSON.String), &scanData); err == nil {
				scan.ScanData = &scanData
			}
		}

		scans = append(scans, &scan)
	}

	return scans, rows.Err()
}

// GetPDSStats returns aggregate statistics
func (s *SQLiteDB) GetPDSStats(ctx context.Context) (*PDSStats, error) {
	query := `
        SELECT 
            COUNT(*) as total_pds,
            SUM(CASE WHEN status = 1 THEN 1 ELSE 0 END) as online_pds,
            SUM(CASE WHEN status = 2 THEN 1 ELSE 0 END) as offline_pds,
            (SELECT AVG(response_time) FROM pds_scans WHERE response_time > 0 
             AND scanned_at > datetime('now', '-1 hour')) as avg_response_time,
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
