package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/atscan/atscanner/internal/log"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/lib/pq"
)

type PostgresDB struct {
	db            *sql.DB
	pool          *pgxpool.Pool
	scanRetention int
}

func NewPostgresDB(connString string) (*PostgresDB, error) {
	log.Info("Connecting to PostgreSQL database...")

	// Open standard sql.DB (for compatibility)
	db, err := sql.Open("pgx", connString)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Connection pool settings
	db.SetMaxOpenConns(50)
	db.SetMaxIdleConns(25)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(2 * time.Minute)

	log.Verbose("  Max open connections: 50")
	log.Verbose("  Max idle connections: 25")
	log.Verbose("  Connection max lifetime: 5m")

	// Test connection
	log.Info("Testing database connection...")
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}
	log.Info("✓ Database connection successful")

	// Also create pgx pool for COPY operations
	log.Verbose("Creating pgx connection pool...")
	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		return nil, fmt.Errorf("failed to create pgx pool: %w", err)
	}
	log.Verbose("✓ Connection pool created")

	return &PostgresDB{
		db:            db,
		pool:          pool,
		scanRetention: 3, // Default
	}, nil
}

func (p *PostgresDB) Close() error {
	if p.pool != nil {
		p.pool.Close()
	}
	return p.db.Close()
}

func (p *PostgresDB) Migrate() error {
	log.Info("Running database migrations...")

	schema := `
    -- Endpoints table (NO user_count, NO ip_info)
    CREATE TABLE IF NOT EXISTS endpoints (
        id BIGSERIAL PRIMARY KEY,
        endpoint_type TEXT NOT NULL DEFAULT 'pds',
        endpoint TEXT NOT NULL,
        server_did TEXT,
        discovered_at TIMESTAMP NOT NULL,
        last_checked TIMESTAMP,
        status INTEGER DEFAULT 0,
        ip TEXT,
        ip_resolved_at TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(endpoint_type, endpoint)
    );

    CREATE INDEX IF NOT EXISTS idx_endpoints_type_endpoint ON endpoints(endpoint_type, endpoint);
    CREATE INDEX IF NOT EXISTS idx_endpoints_status ON endpoints(status);
    CREATE INDEX IF NOT EXISTS idx_endpoints_type ON endpoints(endpoint_type);
    CREATE INDEX IF NOT EXISTS idx_endpoints_ip ON endpoints(ip);
    CREATE INDEX IF NOT EXISTS idx_endpoints_server_did ON endpoints(server_did);
	CREATE INDEX IF NOT EXISTS idx_endpoints_server_did_type_discovered ON endpoints(server_did, endpoint_type, discovered_at);

    -- IP infos table (IP as PRIMARY KEY)
    CREATE TABLE IF NOT EXISTS ip_infos (
        ip TEXT PRIMARY KEY,
        city TEXT,
        country TEXT,
        country_code TEXT,
        asn INTEGER,
        asn_org TEXT,
        is_datacenter BOOLEAN,
        is_vpn BOOLEAN,
        latitude REAL,
        longitude REAL,
        raw_data JSONB,
        fetched_at TIMESTAMP NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_ip_infos_country_code ON ip_infos(country_code);
    CREATE INDEX IF NOT EXISTS idx_ip_infos_asn ON ip_infos(asn);

    -- Endpoint scans (renamed from pds_scans)
	CREATE TABLE IF NOT EXISTS endpoint_scans (
		id BIGSERIAL PRIMARY KEY,
		endpoint_id BIGINT NOT NULL,
		status INTEGER NOT NULL,
		response_time DOUBLE PRECISION,
		user_count BIGINT,
		version TEXT,
		scan_data JSONB,
		scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (endpoint_id) REFERENCES endpoints(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_endpoint_scans_endpoint_status_scanned ON endpoint_scans(endpoint_id, status, scanned_at DESC);
	CREATE INDEX IF NOT EXISTS idx_endpoint_scans_scanned_at ON endpoint_scans(scanned_at);
	CREATE INDEX IF NOT EXISTS idx_endpoint_scans_user_count ON endpoint_scans(user_count DESC NULLS LAST);

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

	-- Minimal dids table
	CREATE TABLE IF NOT EXISTS dids (
		did TEXT PRIMARY KEY,
		handle TEXT,
		pds TEXT,
		bundle_numbers JSONB NOT NULL DEFAULT '[]'::jsonb,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_dids_bundle_numbers ON dids USING gin(bundle_numbers);
	CREATE INDEX IF NOT EXISTS idx_dids_created_at ON dids(created_at);
	CREATE INDEX IF NOT EXISTS idx_dids_handle ON dids(handle);
	CREATE INDEX IF NOT EXISTS idx_dids_pds ON dids(pds);

	-- PDS Repositories table
    CREATE TABLE IF NOT EXISTS pds_repos (
        id BIGSERIAL PRIMARY KEY,
        endpoint_id BIGINT NOT NULL,
        did TEXT NOT NULL,
        head TEXT,
        rev TEXT,
        active BOOLEAN DEFAULT true,
        status TEXT,
        first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (endpoint_id) REFERENCES endpoints(id) ON DELETE CASCADE,
        UNIQUE(endpoint_id, did)
    );

    CREATE INDEX IF NOT EXISTS idx_pds_repos_endpoint ON pds_repos(endpoint_id);
	CREATE INDEX IF NOT EXISTS idx_pds_repos_endpoint_id_desc ON pds_repos(endpoint_id, id DESC);
    CREATE INDEX IF NOT EXISTS idx_pds_repos_did ON pds_repos(did);
    CREATE INDEX IF NOT EXISTS idx_pds_repos_active ON pds_repos(active);
    CREATE INDEX IF NOT EXISTS idx_pds_repos_status ON pds_repos(status);
    CREATE INDEX IF NOT EXISTS idx_pds_repos_last_seen ON pds_repos(last_seen DESC);
    `

	_, err := p.db.Exec(schema)
	if err != nil {
		return err
	}

	log.Info("✓ Database migrations completed successfully")
	return nil
}

// ===== ENDPOINT OPERATIONS =====

func (p *PostgresDB) UpsertEndpoint(ctx context.Context, endpoint *Endpoint) error {
	query := `
        INSERT INTO endpoints (endpoint_type, endpoint, discovered_at, last_checked, status, ip, ip_resolved_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT(endpoint_type, endpoint) DO UPDATE SET
            last_checked = EXCLUDED.last_checked,
            status = EXCLUDED.status,
            ip = CASE 
                WHEN EXCLUDED.ip IS NOT NULL AND EXCLUDED.ip != '' THEN EXCLUDED.ip 
                ELSE endpoints.ip 
            END,
            ip_resolved_at = CASE
                WHEN EXCLUDED.ip IS NOT NULL AND EXCLUDED.ip != '' THEN EXCLUDED.ip_resolved_at
                ELSE endpoints.ip_resolved_at
            END,
            updated_at = CURRENT_TIMESTAMP
        RETURNING id
    `
	err := p.db.QueryRowContext(ctx, query,
		endpoint.EndpointType, endpoint.Endpoint, endpoint.DiscoveredAt,
		endpoint.LastChecked, endpoint.Status, endpoint.IP, endpoint.IPResolvedAt).Scan(&endpoint.ID)
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
        SELECT id, endpoint_type, endpoint, discovered_at, last_checked, status, 
               ip, ip_resolved_at, updated_at
        FROM endpoints 
        WHERE endpoint = $1 AND endpoint_type = $2
    `

	var ep Endpoint
	var lastChecked, ipResolvedAt sql.NullTime
	var ip sql.NullString

	err := p.db.QueryRowContext(ctx, query, endpoint, endpointType).Scan(
		&ep.ID, &ep.EndpointType, &ep.Endpoint, &ep.DiscoveredAt, &lastChecked,
		&ep.Status, &ip, &ipResolvedAt, &ep.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	if lastChecked.Valid {
		ep.LastChecked = lastChecked.Time
	}
	if ip.Valid {
		ep.IP = ip.String
	}
	if ipResolvedAt.Valid {
		ep.IPResolvedAt = ipResolvedAt.Time
	}

	return &ep, nil
}

func (p *PostgresDB) GetEndpoints(ctx context.Context, filter *EndpointFilter) ([]*Endpoint, error) {
	query := `
		SELECT DISTINCT ON (COALESCE(server_did, id::text))
			id, endpoint_type, endpoint, server_did, discovered_at, last_checked, status, 
			ip, ip_resolved_at, updated_at
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

		// Filter for stale endpoints only
		if filter.OnlyStale && filter.RecheckInterval > 0 {
			cutoffTime := time.Now().UTC().Add(-filter.RecheckInterval)
			query += fmt.Sprintf(" AND (last_checked IS NULL OR last_checked < $%d)", argIdx)
			args = append(args, cutoffTime)
			argIdx++
		}
	}

	// NEW: Order by server_did and discovered_at to get primary endpoints
	query += " ORDER BY COALESCE(server_did, id::text), discovered_at ASC"

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
		var lastChecked, ipResolvedAt sql.NullTime
		var ip, serverDID sql.NullString

		err := rows.Scan(
			&ep.ID, &ep.EndpointType, &ep.Endpoint, &serverDID, &ep.DiscoveredAt, &lastChecked,
			&ep.Status, &ip, &ipResolvedAt, &ep.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		if serverDID.Valid {
			ep.ServerDID = serverDID.String
		}
		if lastChecked.Valid {
			ep.LastChecked = lastChecked.Time
		}
		if ip.Valid {
			ep.IP = ip.String
		}
		if ipResolvedAt.Valid {
			ep.IPResolvedAt = ipResolvedAt.Time
		}

		endpoints = append(endpoints, &ep)
	}

	return endpoints, rows.Err()
}

func (p *PostgresDB) UpdateEndpointStatus(ctx context.Context, endpointID int64, update *EndpointUpdate) error {
	query := `
        UPDATE endpoints 
        SET status = $1, last_checked = $2, updated_at = $3
        WHERE id = $4
    `
	_, err := p.db.ExecContext(ctx, query, update.Status, update.LastChecked, time.Now().UTC(), endpointID)
	return err
}

func (p *PostgresDB) UpdateEndpointIP(ctx context.Context, endpointID int64, ip string, resolvedAt time.Time) error {
	query := `
        UPDATE endpoints 
        SET ip = $1, ip_resolved_at = $2, updated_at = $3
        WHERE id = $4
    `
	_, err := p.db.ExecContext(ctx, query, ip, resolvedAt, time.Now().UTC(), endpointID)
	return err
}

func (p *PostgresDB) UpdateEndpointServerDID(ctx context.Context, endpointID int64, serverDID string) error {
	query := `
		UPDATE endpoints 
		SET server_did = $1, updated_at = $2
		WHERE id = $3
	`
	_, err := p.db.ExecContext(ctx, query, serverDID, time.Now().UTC(), endpointID)
	return err
}

func (p *PostgresDB) GetDuplicateEndpoints(ctx context.Context) (map[string][]string, error) {
	query := `
		SELECT server_did, array_agg(endpoint ORDER BY discovered_at ASC) as endpoints
		FROM endpoints
		WHERE server_did IS NOT NULL 
		  AND server_did != ''
		  AND endpoint_type = 'pds'
		GROUP BY server_did
		HAVING COUNT(*) > 1
		ORDER BY COUNT(*) DESC
	`

	rows, err := p.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	duplicates := make(map[string][]string)
	for rows.Next() {
		var serverDID string
		var endpoints []string

		err := rows.Scan(&serverDID, pq.Array(&endpoints))
		if err != nil {
			return nil, err
		}

		duplicates[serverDID] = endpoints
	}

	return duplicates, rows.Err()
}

// ===== SCAN OPERATIONS =====

func (p *PostgresDB) SetScanRetention(retention int) {
	p.scanRetention = retention
}

func (p *PostgresDB) SaveEndpointScan(ctx context.Context, scan *EndpointScan) error {
	var scanDataJSON []byte
	if scan.ScanData != nil {
		scanDataJSON, _ = json.Marshal(scan.ScanData)
	}

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	query := `
		INSERT INTO endpoint_scans (endpoint_id, status, response_time, user_count, version, scan_data, scanned_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err = tx.ExecContext(ctx, query, scan.EndpointID, scan.Status, scan.ResponseTime, scan.UserCount, scan.Version, scanDataJSON, scan.ScannedAt)
	if err != nil {
		return err
	}

	// Use configured retention value
	cleanupQuery := `
		DELETE FROM endpoint_scans
		WHERE endpoint_id = $1
		AND id NOT IN (
			SELECT id
			FROM endpoint_scans
			WHERE endpoint_id = $1
			ORDER BY scanned_at DESC
			LIMIT $2
		)
	`
	_, err = tx.ExecContext(ctx, cleanupQuery, scan.EndpointID, p.scanRetention)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (p *PostgresDB) GetEndpointScans(ctx context.Context, endpointID int64, limit int) ([]*EndpointScan, error) {
	query := `
        SELECT id, endpoint_id, status, response_time, user_count, version, scan_data, scanned_at
        FROM endpoint_scans
        WHERE endpoint_id = $1
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
		var userCount sql.NullInt64
		var version sql.NullString // NEW
		var scanDataJSON []byte

		err := rows.Scan(&scan.ID, &scan.EndpointID, &scan.Status, &responseTime, &userCount, &version, &scanDataJSON, &scan.ScannedAt)
		if err != nil {
			return nil, err
		}

		if responseTime.Valid {
			scan.ResponseTime = responseTime.Float64
		}

		if userCount.Valid {
			scan.UserCount = userCount.Int64
		}

		if version.Valid { // NEW
			scan.Version = version.String
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

// ===== PDS VIRTUAL ENDPOINTS =====

func (p *PostgresDB) GetPDSList(ctx context.Context, filter *EndpointFilter) ([]*PDSListItem, error) {
	query := `
		WITH unique_servers AS (
			SELECT DISTINCT ON (COALESCE(server_did, id::text))
				id,
				endpoint,
				server_did,
				discovered_at,
				last_checked,
				status,
				ip
			FROM endpoints
			WHERE endpoint_type = 'pds'
			ORDER BY COALESCE(server_did, id::text), discovered_at ASC
		)
		SELECT 
			e.id, e.endpoint, e.server_did, e.discovered_at, e.last_checked, e.status, e.ip,
			latest.user_count, latest.response_time, latest.version, latest.scanned_at,
			i.city, i.country, i.country_code, i.asn, i.asn_org,
			i.is_datacenter, i.is_vpn, i.latitude, i.longitude
		FROM unique_servers e
		LEFT JOIN LATERAL (
			SELECT 
				user_count,
				response_time,
				version,
				scanned_at
			FROM endpoint_scans
			WHERE endpoint_id = e.id AND status = 1
			ORDER BY scanned_at DESC
			LIMIT 1
		) latest ON true
		LEFT JOIN ip_infos i ON e.ip = i.ip
		WHERE 1=1
	`

	args := []interface{}{}
	argIdx := 1

	if filter != nil {
		if filter.Status != "" {
			statusInt := EndpointStatusUnknown
			switch filter.Status {
			case "online":
				statusInt = EndpointStatusOnline
			case "offline":
				statusInt = EndpointStatusOffline
			}
			query += fmt.Sprintf(" AND e.status = $%d", argIdx)
			args = append(args, statusInt)
			argIdx++
		}

		if filter.MinUserCount > 0 {
			query += fmt.Sprintf(" AND latest.user_count >= $%d", argIdx)
			args = append(args, filter.MinUserCount)
			argIdx++
		}
	}

	query += " ORDER BY latest.user_count DESC NULLS LAST"

	if filter != nil && filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
		args = append(args, filter.Limit, filter.Offset)
	}

	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []*PDSListItem
	for rows.Next() {
		item := &PDSListItem{}
		var ip, serverDID, city, country, countryCode, asnOrg sql.NullString
		var asn sql.NullInt32
		var isDatacenter, isVPN sql.NullBool
		var lat, lon sql.NullFloat64
		var userCount sql.NullInt32
		var responseTime sql.NullFloat64
		var version sql.NullString
		var scannedAt sql.NullTime

		err := rows.Scan(
			&item.ID, &item.Endpoint, &serverDID, &item.DiscoveredAt, &item.LastChecked, &item.Status, &ip,
			&userCount, &responseTime, &version, &scannedAt,
			&city, &country, &countryCode, &asn, &asnOrg,
			&isDatacenter, &isVPN, &lat, &lon,
		)
		if err != nil {
			return nil, err
		}

		if ip.Valid {
			item.IP = ip.String
		}
		if serverDID.Valid {
			item.ServerDID = serverDID.String
		}

		// Add latest scan data if available
		if userCount.Valid {
			item.LatestScan = &struct {
				UserCount    int
				ResponseTime float64
				Version      string
				ScannedAt    time.Time
			}{
				UserCount:    int(userCount.Int32),
				ResponseTime: responseTime.Float64,
				Version:      version.String,
				ScannedAt:    scannedAt.Time,
			}
		}

		// Add IP info if available
		if city.Valid || country.Valid {
			item.IPInfo = &IPInfo{
				IP:           ip.String,
				City:         city.String,
				Country:      country.String,
				CountryCode:  countryCode.String,
				ASN:          int(asn.Int32),
				ASNOrg:       asnOrg.String,
				IsDatacenter: isDatacenter.Bool,
				IsVPN:        isVPN.Bool,
				Latitude:     float32(lat.Float64),
				Longitude:    float32(lon.Float64),
			}
		}

		items = append(items, item)
	}

	return items, rows.Err()
}

func (p *PostgresDB) GetPDSDetail(ctx context.Context, endpoint string) (*PDSDetail, error) {
	query := `
		WITH target_endpoint AS (
			SELECT 
				e.id, 
				e.endpoint, 
				e.server_did, 
				e.discovered_at, 
				e.last_checked, 
				e.status, 
				e.ip
			FROM endpoints e
			WHERE e.endpoint = $1 AND e.endpoint_type = 'pds'
		),
		aliases_agg AS (
			SELECT 
				te.server_did,
				array_agg(e.endpoint ORDER BY e.discovered_at) FILTER (WHERE e.endpoint != te.endpoint) as aliases,
				MIN(e.discovered_at) as first_discovered_at
			FROM target_endpoint te
			LEFT JOIN endpoints e ON te.server_did = e.server_did 
				AND e.endpoint_type = 'pds'
				AND te.server_did IS NOT NULL
			GROUP BY te.server_did
		)
		SELECT 
			te.id, 
			te.endpoint, 
			te.server_did, 
			te.discovered_at, 
			te.last_checked, 
			te.status, 
			te.ip,
			latest.user_count,
			latest.response_time,
			latest.version,
			latest.scan_data->'metadata'->'server_info' as server_info,
			latest.scanned_at,
			i.city, i.country, i.country_code, i.asn, i.asn_org,
			i.is_datacenter, i.is_vpn, i.latitude, i.longitude,
			i.raw_data,
			COALESCE(aa.aliases, ARRAY[]::text[]) as aliases,
			aa.first_discovered_at
		FROM target_endpoint te
		LEFT JOIN aliases_agg aa ON te.server_did = aa.server_did
		LEFT JOIN LATERAL (
			SELECT scan_data, response_time, version, scanned_at, user_count
			FROM endpoint_scans
			WHERE endpoint_id = te.id
			ORDER BY scanned_at DESC
			LIMIT 1
		) latest ON true
		LEFT JOIN ip_infos i ON te.ip = i.ip
	`

	detail := &PDSDetail{}
	var ip, city, country, countryCode, asnOrg, serverDID sql.NullString
	var asn sql.NullInt32
	var isDatacenter, isVPN sql.NullBool
	var lat, lon sql.NullFloat64
	var userCount sql.NullInt32
	var responseTime sql.NullFloat64
	var version sql.NullString
	var serverInfoJSON []byte
	var scannedAt sql.NullTime
	var rawDataJSON []byte
	var aliases []string
	var firstDiscoveredAt sql.NullTime

	err := p.db.QueryRowContext(ctx, query, endpoint).Scan(
		&detail.ID, &detail.Endpoint, &serverDID, &detail.DiscoveredAt, &detail.LastChecked, &detail.Status, &ip,
		&userCount, &responseTime, &version, &serverInfoJSON, &scannedAt,
		&city, &country, &countryCode, &asn, &asnOrg,
		&isDatacenter, &isVPN, &lat, &lon,
		&rawDataJSON,
		pq.Array(&aliases),
		&firstDiscoveredAt,
	)
	if err != nil {
		return nil, err
	}

	if ip.Valid {
		detail.IP = ip.String
	}

	if serverDID.Valid {
		detail.ServerDID = serverDID.String
	}

	// Set aliases and is_primary
	detail.Aliases = aliases
	if serverDID.Valid && serverDID.String != "" && firstDiscoveredAt.Valid {
		// Has server_did - check if this is the first discovered
		detail.IsPrimary = detail.DiscoveredAt.Equal(firstDiscoveredAt.Time) ||
			detail.DiscoveredAt.Before(firstDiscoveredAt.Time)
	} else {
		// No server_did means unique server
		detail.IsPrimary = true
	}

	// Parse latest scan data
	if userCount.Valid {
		var serverInfo interface{}
		if len(serverInfoJSON) > 0 {
			json.Unmarshal(serverInfoJSON, &serverInfo)
		}

		detail.LatestScan = &struct {
			UserCount    int
			ResponseTime float64
			Version      string
			ServerInfo   interface{}
			ScannedAt    time.Time
		}{
			UserCount:    int(userCount.Int32),
			ResponseTime: responseTime.Float64,
			Version:      version.String,
			ServerInfo:   serverInfo,
			ScannedAt:    scannedAt.Time,
		}
	}

	// Parse IP info
	if city.Valid || country.Valid {
		detail.IPInfo = &IPInfo{
			IP:           ip.String,
			City:         city.String,
			Country:      country.String,
			CountryCode:  countryCode.String,
			ASN:          int(asn.Int32),
			ASNOrg:       asnOrg.String,
			IsDatacenter: isDatacenter.Bool,
			IsVPN:        isVPN.Bool,
			Latitude:     float32(lat.Float64),
			Longitude:    float32(lon.Float64),
		}

		if len(rawDataJSON) > 0 {
			json.Unmarshal(rawDataJSON, &detail.IPInfo.RawData)
		}
	}

	return detail, nil
}

func (p *PostgresDB) GetPDSStats(ctx context.Context) (*PDSStats, error) {
	query := `
		WITH unique_servers AS (
			SELECT DISTINCT ON (COALESCE(server_did, id::text))
				id,
				COALESCE(server_did, id::text) as server_identity,
				status
			FROM endpoints
			WHERE endpoint_type = 'pds'
			ORDER BY COALESCE(server_did, id::text), discovered_at ASC
		),
		latest_scans AS (
			SELECT DISTINCT ON (us.id)
				us.id,
				es.user_count,
				us.status
			FROM unique_servers us
			LEFT JOIN endpoint_scans es ON us.id = es.endpoint_id
			ORDER BY us.id, es.scanned_at DESC
		)
		SELECT 
			COUNT(*) as total,
			SUM(CASE WHEN status = 1 THEN 1 ELSE 0 END) as online,
			SUM(CASE WHEN status = 2 THEN 1 ELSE 0 END) as offline,
			SUM(COALESCE(user_count, 0)) as total_users
		FROM latest_scans
	`

	stats := &PDSStats{}
	err := p.db.QueryRowContext(ctx, query).Scan(
		&stats.TotalEndpoints, &stats.OnlineEndpoints, &stats.OfflineEndpoints, &stats.TotalDIDs,
	)

	return stats, err
}

func (p *PostgresDB) GetEndpointStats(ctx context.Context) (*EndpointStats, error) {
	query := `
        SELECT 
            COUNT(*) as total_endpoints,
            SUM(CASE WHEN status = 1 THEN 1 ELSE 0 END) as online_endpoints,
            SUM(CASE WHEN status = 2 THEN 1 ELSE 0 END) as offline_endpoints
        FROM endpoints
    `

	var stats EndpointStats
	err := p.db.QueryRowContext(ctx, query).Scan(
		&stats.TotalEndpoints, &stats.OnlineEndpoints, &stats.OfflineEndpoints,
	)
	if err != nil {
		return nil, err
	}

	// Get average response time from recent scans
	avgQuery := `
        SELECT AVG(response_time) 
        FROM endpoint_scans 
        WHERE response_time > 0 AND scanned_at > NOW() - INTERVAL '1 hour'
    `
	var avgResponseTime sql.NullFloat64
	_ = p.db.QueryRowContext(ctx, avgQuery).Scan(&avgResponseTime)
	if avgResponseTime.Valid {
		stats.AvgResponseTime = avgResponseTime.Float64
	}

	// Get counts by type
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

	// Get total DIDs from latest PDS scans
	didQuery := `
		WITH unique_servers AS (
			SELECT DISTINCT ON (COALESCE(e.server_did, e.id::text))
				e.id
			FROM endpoints e
			WHERE e.endpoint_type = 'pds'
			ORDER BY COALESCE(e.server_did, e.id::text), e.discovered_at ASC
		),
		latest_pds_scans AS (
			SELECT DISTINCT ON (us.id)
				us.id,
				es.user_count
			FROM unique_servers us
			LEFT JOIN endpoint_scans es ON us.id = es.endpoint_id
			ORDER BY us.id, es.scanned_at DESC
        )
        SELECT SUM(user_count) FROM latest_pds_scans
    `
	var totalDIDs sql.NullInt64
	_ = p.db.QueryRowContext(ctx, didQuery).Scan(&totalDIDs)
	if totalDIDs.Valid {
		stats.TotalDIDs = totalDIDs.Int64
	}

	return &stats, err
}

// ===== IP INFO OPERATIONS =====

func (p *PostgresDB) UpsertIPInfo(ctx context.Context, ip string, ipInfo map[string]interface{}) error {
	rawDataJSON, _ := json.Marshal(ipInfo)

	// Extract fields from ipInfo map
	city := extractString(ipInfo, "location", "city")
	country := extractString(ipInfo, "location", "country")
	countryCode := extractString(ipInfo, "location", "country_code")
	asn := extractInt(ipInfo, "asn", "asn")
	asnOrg := extractString(ipInfo, "asn", "org")

	// Extract top-level boolean flags
	isDatacenter := false
	if val, ok := ipInfo["is_datacenter"].(bool); ok {
		isDatacenter = val
	}

	isVPN := false
	if val, ok := ipInfo["is_vpn"].(bool); ok {
		isVPN = val
	}

	lat := extractFloat(ipInfo, "location", "latitude")
	lon := extractFloat(ipInfo, "location", "longitude")

	query := `
        INSERT INTO ip_infos (ip, city, country, country_code, asn, asn_org, is_datacenter, is_vpn, latitude, longitude, raw_data, fetched_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        ON CONFLICT(ip) DO UPDATE SET
            city = EXCLUDED.city,
            country = EXCLUDED.country,
            country_code = EXCLUDED.country_code,
            asn = EXCLUDED.asn,
            asn_org = EXCLUDED.asn_org,
            is_datacenter = EXCLUDED.is_datacenter,
            is_vpn = EXCLUDED.is_vpn,
            latitude = EXCLUDED.latitude,
            longitude = EXCLUDED.longitude,
            raw_data = EXCLUDED.raw_data,
            fetched_at = EXCLUDED.fetched_at,
            updated_at = CURRENT_TIMESTAMP
    `
	_, err := p.db.ExecContext(ctx, query, ip, city, country, countryCode, asn, asnOrg, isDatacenter, isVPN, lat, lon, rawDataJSON, time.Now().UTC())
	return err
}

func (p *PostgresDB) GetIPInfo(ctx context.Context, ip string) (*IPInfo, error) {
	query := `
        SELECT ip, city, country, country_code, asn, asn_org, is_datacenter, is_vpn, 
               latitude, longitude, raw_data, fetched_at, updated_at
        FROM ip_infos
        WHERE ip = $1
    `

	info := &IPInfo{}
	var rawDataJSON []byte

	err := p.db.QueryRowContext(ctx, query, ip).Scan(
		&info.IP, &info.City, &info.Country, &info.CountryCode, &info.ASN, &info.ASNOrg,
		&info.IsDatacenter, &info.IsVPN, &info.Latitude, &info.Longitude,
		&rawDataJSON, &info.FetchedAt, &info.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	if len(rawDataJSON) > 0 {
		json.Unmarshal(rawDataJSON, &info.RawData)
	}

	return info, nil
}

func (p *PostgresDB) ShouldUpdateIPInfo(ctx context.Context, ip string) (bool, bool, error) {
	query := `SELECT fetched_at FROM ip_infos WHERE ip = $1`

	var fetchedAt time.Time
	err := p.db.QueryRowContext(ctx, query, ip).Scan(&fetchedAt)
	if err == sql.ErrNoRows {
		return false, true, nil // Doesn't exist, needs update
	}
	if err != nil {
		return false, false, err
	}

	// Check if older than 30 days
	needsUpdate := time.Since(fetchedAt) > 30*24*time.Hour
	return true, needsUpdate, nil
}

// ===== HELPER FUNCTIONS =====

func extractString(data map[string]interface{}, keys ...string) string {
	current := data
	for i, key := range keys {
		if i == len(keys)-1 {
			if val, ok := current[key].(string); ok {
				return val
			}
			return ""
		}
		if nested, ok := current[key].(map[string]interface{}); ok {
			current = nested
		} else {
			return ""
		}
	}
	return ""
}

func extractInt(data map[string]interface{}, keys ...string) int {
	current := data
	for i, key := range keys {
		if i == len(keys)-1 {
			if val, ok := current[key].(float64); ok {
				return int(val)
			}
			if val, ok := current[key].(int); ok {
				return val
			}
			return 0
		}
		if nested, ok := current[key].(map[string]interface{}); ok {
			current = nested
		} else {
			return 0
		}
	}
	return 0
}

func extractFloat(data map[string]interface{}, keys ...string) float32 {
	current := data
	for i, key := range keys {
		if i == len(keys)-1 {
			if val, ok := current[key].(float64); ok {
				return float32(val)
			}
			return 0
		}
		if nested, ok := current[key].(map[string]interface{}); ok {
			current = nested
		} else {
			return 0
		}
	}
	return 0
}

func extractBool(data map[string]interface{}, keys ...string) bool {
	current := data
	for i, key := range keys {
		if i == len(keys)-1 {
			if val, ok := current[key].(bool); ok {
				return val
			}
			// Check if it's a string that matches (for type="hosting")
			if val, ok := current[key].(string); ok {
				// For cases like company.type == "hosting"
				expectedValue := keys[len(keys)-1]
				return val == expectedValue
			}
			return false
		}
		if nested, ok := current[key].(map[string]interface{}); ok {
			current = nested
		} else {
			return false
		}
	}
	return false
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

func (p *PostgresDB) GetPLCHistory(ctx context.Context, limit int, fromBundle int) ([]*PLCHistoryPoint, error) {
	query := `
		WITH daily_stats AS (
			SELECT 
				DATE(start_time) as date,
				MAX(bundle_number) as last_bundle,
				COUNT(*) as bundle_count,
				SUM(uncompressed_size) as total_uncompressed,
				SUM(compressed_size) as total_compressed,
				MAX(cumulative_uncompressed_size) as cumulative_uncompressed,
				MAX(cumulative_compressed_size) as cumulative_compressed
			FROM plc_bundles
			WHERE bundle_number >= $1
			GROUP BY DATE(start_time)
		)
		SELECT 
			date::text,
			last_bundle,
			SUM(bundle_count * 10000) OVER (ORDER BY date) as cumulative_operations,
			total_uncompressed,
			total_compressed,
			cumulative_uncompressed,
			cumulative_compressed
		FROM daily_stats
		ORDER BY date ASC
	`

	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := p.db.QueryContext(ctx, query, fromBundle)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []*PLCHistoryPoint
	for rows.Next() {
		var point PLCHistoryPoint
		var cumulativeOps int64

		err := rows.Scan(
			&point.Date,
			&point.BundleNumber,
			&cumulativeOps,
			&point.UncompressedSize,
			&point.CompressedSize,
			&point.CumulativeUncompressed,
			&point.CumulativeCompressed,
		)
		if err != nil {
			return nil, err
		}

		point.OperationCount = int(cumulativeOps)

		history = append(history, &point)
	}

	return history, rows.Err()
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

func (p *PostgresDB) UpsertDID(ctx context.Context, did string, bundleNum int, handle, pds string) error {
	query := `
		INSERT INTO dids (did, handle, pds, bundle_numbers, created_at)
		VALUES ($1, $2, $3, jsonb_build_array($4::integer), CURRENT_TIMESTAMP)
		ON CONFLICT(did) DO UPDATE SET
			handle = EXCLUDED.handle,
			pds = EXCLUDED.pds,
			bundle_numbers = CASE 
				WHEN dids.bundle_numbers @> jsonb_build_array($4::integer) THEN dids.bundle_numbers
				ELSE dids.bundle_numbers || jsonb_build_array($4::integer)
			END,
			updated_at = CURRENT_TIMESTAMP
	`
	_, err := p.db.ExecContext(ctx, query, did, handle, pds, bundleNum)
	return err
}

// UpsertDIDFromMempool creates/updates DID record without adding to bundle_numbers
func (p *PostgresDB) UpsertDIDFromMempool(ctx context.Context, did string, handle, pds string) error {
	query := `
		INSERT INTO dids (did, handle, pds, bundle_numbers, created_at)
		VALUES ($1, $2, $3, '[]'::jsonb, CURRENT_TIMESTAMP)
		ON CONFLICT(did) DO UPDATE SET
			handle = EXCLUDED.handle,
			pds = EXCLUDED.pds,
			updated_at = CURRENT_TIMESTAMP
	`
	_, err := p.db.ExecContext(ctx, query, did, handle, pds)
	return err
}

func (p *PostgresDB) GetDIDRecord(ctx context.Context, did string) (*DIDRecord, error) {
	query := `
		SELECT did, handle, pds, bundle_numbers, created_at
		FROM dids
		WHERE did = $1
	`

	var record DIDRecord
	var bundleNumbersJSON []byte
	var handle, pds sql.NullString

	err := p.db.QueryRowContext(ctx, query, did).Scan(
		&record.DID,
		&handle,
		&pds,
		&bundleNumbersJSON,
		&record.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	if handle.Valid {
		record.Handle = handle.String
	}
	if pds.Valid {
		record.CurrentPDS = pds.String
	}

	if err := json.Unmarshal(bundleNumbersJSON, &record.BundleNumbers); err != nil {
		return nil, err
	}

	return &record, nil
}

func (p *PostgresDB) GetDIDByHandle(ctx context.Context, handle string) (*DIDRecord, error) {
	query := `
		SELECT did, handle, pds, bundle_numbers, created_at
		FROM dids
		WHERE handle = $1
	`

	var record DIDRecord
	var bundleNumbersJSON []byte
	var recordHandle, pds sql.NullString

	err := p.db.QueryRowContext(ctx, query, handle).Scan(
		&record.DID,
		&recordHandle,
		&pds,
		&bundleNumbersJSON,
		&record.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	if recordHandle.Valid {
		record.Handle = recordHandle.String
	}
	if pds.Valid {
		record.CurrentPDS = pds.String
	}

	if err := json.Unmarshal(bundleNumbersJSON, &record.BundleNumbers); err != nil {
		return nil, err
	}

	return &record, nil
}

// GetGlobalDIDInfo retrieves consolidated DID info from 'dids' and 'pds_repos'
func (p *PostgresDB) GetGlobalDIDInfo(ctx context.Context, did string) (*GlobalDIDInfo, error) {
	query := `
		WITH primary_endpoints AS (
		  SELECT DISTINCT ON (COALESCE(server_did, id::text))
			id
		  FROM endpoints
		  WHERE endpoint_type = 'pds'
		  ORDER BY COALESCE(server_did, id::text), discovered_at ASC
		)
		SELECT
		  d.did,
		  d.handle,
		  d.pds,
		  d.bundle_numbers,
		  d.created_at,
		  COALESCE(
			jsonb_agg(
			  jsonb_build_object(
				'id', pr.id,
				'endpoint_id', pr.endpoint_id,
				'endpoint', e.endpoint,
				'did', pr.did,
				'head', pr.head,
				'rev', pr.rev,
				'active', pr.active,
				'status', pr.status,
				'first_seen', pr.first_seen AT TIME ZONE 'UTC',
				'last_seen', pr.last_seen AT TIME ZONE 'UTC',
				'updated_at', pr.updated_at AT TIME ZONE 'UTC'
			  )
			ORDER BY pr.last_seen DESC
			) FILTER (
				WHERE pr.id IS NOT NULL AND pe.id IS NOT NULL
			),
			'[]'::jsonb
		  ) AS hosting_on
		FROM
		  dids d
		LEFT JOIN
		  pds_repos pr ON d.did = pr.did
		LEFT JOIN
		  endpoints e ON pr.endpoint_id = e.id
		LEFT JOIN
		  primary_endpoints pe ON pr.endpoint_id = pe.id
		WHERE
		  d.did = $1
		GROUP BY
		  d.did, d.handle, d.pds, d.bundle_numbers, d.created_at
	`

	var info GlobalDIDInfo
	var bundleNumbersJSON []byte
	var hostingOnJSON []byte
	var handle, pds sql.NullString

	err := p.db.QueryRowContext(ctx, query, did).Scan(
		&info.DID,
		&handle,
		&pds,
		&bundleNumbersJSON,
		&info.CreatedAt,
		&hostingOnJSON,
	)
	if err != nil {
		return nil, err
	}

	if handle.Valid {
		info.Handle = handle.String
	}
	if pds.Valid {
		info.CurrentPDS = pds.String
	}

	if err := json.Unmarshal(bundleNumbersJSON, &info.BundleNumbers); err != nil {
		return nil, fmt.Errorf("failed to unmarshal bundle_numbers: %w", err)
	}

	if err := json.Unmarshal(hostingOnJSON, &info.HostingOn); err != nil {
		return nil, fmt.Errorf("failed to unmarshal hosting_on: %w", err)
	}

	return &info, nil
}

func (p *PostgresDB) AddBundleDIDs(ctx context.Context, bundleNum int, dids []string) error {
	if len(dids) == 0 {
		return nil
	}

	// Acquire a connection from the pool
	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	// Start transaction
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Create temporary table
	_, err = tx.Exec(ctx, `
		CREATE TEMP TABLE temp_dids (did TEXT PRIMARY KEY) ON COMMIT DROP
	`)
	if err != nil {
		return err
	}

	// Use COPY for blazing fast bulk insert
	_, err = tx.Conn().CopyFrom(
		ctx,
		pgx.Identifier{"temp_dids"},
		[]string{"did"},
		pgx.CopyFromSlice(len(dids), func(i int) ([]interface{}, error) {
			return []interface{}{dids[i]}, nil
		}),
	)
	if err != nil {
		return err
	}

	// Step 1: Insert new DIDs
	_, err = tx.Exec(ctx, `
		INSERT INTO dids (did, bundle_numbers, created_at)
		SELECT td.did, $1::jsonb, CURRENT_TIMESTAMP
		FROM temp_dids td
		WHERE NOT EXISTS (SELECT 1 FROM dids WHERE dids.did = td.did)
	`, fmt.Sprintf("[%d]", bundleNum))

	if err != nil {
		return err
	}

	// Step 2: Update existing DIDs
	_, err = tx.Exec(ctx, `
		UPDATE dids
		SET bundle_numbers = bundle_numbers || $1::jsonb
		FROM temp_dids
		WHERE dids.did = temp_dids.did
		AND NOT (bundle_numbers @> $1::jsonb)
	`, fmt.Sprintf("[%d]", bundleNum))

	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (p *PostgresDB) GetTotalDIDCount(ctx context.Context) (int64, error) {
	query := "SELECT COUNT(*) FROM dids"
	var count int64
	err := p.db.QueryRowContext(ctx, query).Scan(&count)
	return count, err
}

func (p *PostgresDB) GetCountryLeaderboard(ctx context.Context) ([]*CountryStats, error) {
	query := `
		WITH unique_servers AS (
			SELECT DISTINCT ON (COALESCE(e.server_did, e.id::text))
				e.id,
				e.ip,
				e.status
			FROM endpoints e
			WHERE e.endpoint_type = 'pds'
			ORDER BY COALESCE(e.server_did, e.id::text), e.discovered_at ASC
		),
		pds_by_country AS (
			SELECT 
				i.country,
				i.country_code,
				COUNT(DISTINCT us.id) as active_pds_count,
				SUM(latest.user_count) as total_users,
				AVG(latest.response_time) as avg_response_time
			FROM unique_servers us
			JOIN ip_infos i ON us.ip = i.ip
			LEFT JOIN LATERAL (
				SELECT user_count, response_time
				FROM endpoint_scans
				WHERE endpoint_id = us.id
				ORDER BY scanned_at DESC
				LIMIT 1
			) latest ON true
			WHERE us.status = 1
			  AND i.country IS NOT NULL
			  AND i.country != ''
			GROUP BY i.country, i.country_code
		),
		totals AS (
			SELECT 
				SUM(active_pds_count) as total_pds,
				SUM(total_users) as total_users_global
			FROM pds_by_country
		)
		SELECT 
			pbc.country,
			pbc.country_code,
			pbc.active_pds_count,
			ROUND((pbc.active_pds_count * 100.0 / NULLIF(t.total_pds, 0))::numeric, 2) as pds_percentage,
			COALESCE(pbc.total_users, 0) as total_users,
			ROUND((COALESCE(pbc.total_users, 0) * 100.0 / NULLIF(t.total_users_global, 0))::numeric, 2) as users_percentage,
			ROUND(COALESCE(pbc.avg_response_time, 0)::numeric, 2) as avg_response_time_ms
		FROM pds_by_country pbc
		CROSS JOIN totals t
		ORDER BY pbc.active_pds_count DESC
	`

	rows, err := p.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []*CountryStats
	for rows.Next() {
		var s CountryStats
		var pdsPercentage, usersPercentage sql.NullFloat64

		err := rows.Scan(
			&s.Country,
			&s.CountryCode,
			&s.ActivePDSCount,
			&pdsPercentage,
			&s.TotalUsers,
			&usersPercentage,
			&s.AvgResponseTimeMS,
		)
		if err != nil {
			return nil, err
		}

		if pdsPercentage.Valid {
			s.PDSPercentage = pdsPercentage.Float64
		}
		if usersPercentage.Valid {
			s.UsersPercentage = usersPercentage.Float64
		}

		stats = append(stats, &s)
	}

	return stats, rows.Err()
}

func (p *PostgresDB) GetVersionStats(ctx context.Context) ([]*VersionStats, error) {
	query := `
		WITH unique_servers AS (
			SELECT DISTINCT ON (COALESCE(e.server_did, e.id::text))
				e.id
			FROM endpoints e
			WHERE e.endpoint_type = 'pds'
			  AND e.status = 1
			ORDER BY COALESCE(e.server_did, e.id::text), e.discovered_at ASC
		),
		latest_scans AS (
			SELECT DISTINCT ON (us.id)
				us.id,
				es.version,
				es.user_count,
				es.scanned_at
			FROM unique_servers us
			JOIN endpoint_scans es ON us.id = es.endpoint_id
			WHERE es.version IS NOT NULL
			  AND es.version != ''
			ORDER BY us.id, es.scanned_at DESC
		),
		version_groups AS (
			SELECT 
				version,
				COUNT(*) as pds_count,
				SUM(user_count) as total_users,
				MIN(scanned_at) as first_seen,
				MAX(scanned_at) as last_seen
			FROM latest_scans
			GROUP BY version
		),
		totals AS (
			SELECT 
				SUM(pds_count) as total_pds,
				SUM(total_users) as total_users_global
			FROM version_groups
		)
		SELECT 
			vg.version,
			vg.pds_count,
			(vg.pds_count * 100.0 / NULLIF(t.total_pds, 0))::numeric as percentage,
			COALESCE(vg.total_users, 0) as total_users,
			(COALESCE(vg.total_users, 0) * 100.0 / NULLIF(t.total_users_global, 0))::numeric as users_percentage,
			vg.first_seen,
			vg.last_seen
		FROM version_groups vg
		CROSS JOIN totals t
		ORDER BY vg.pds_count DESC
	`

	rows, err := p.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []*VersionStats
	for rows.Next() {
		var s VersionStats
		var percentage, usersPercentage sql.NullFloat64

		err := rows.Scan(
			&s.Version,
			&s.PDSCount,
			&percentage,
			&s.TotalUsers,
			&usersPercentage,
			&s.FirstSeen,
			&s.LastSeen,
		)
		if err != nil {
			return nil, err
		}

		if percentage.Valid {
			s.Percentage = percentage.Float64
			s.PercentageText = formatPercentage(percentage.Float64)
		}
		if usersPercentage.Valid {
			s.UsersPercentage = usersPercentage.Float64
		}

		stats = append(stats, &s)
	}

	return stats, rows.Err()
}

// Helper function (add if not already present)
func formatPercentage(pct float64) string {
	if pct >= 10 {
		return fmt.Sprintf("%.2f%%", pct)
	} else if pct >= 1 {
		return fmt.Sprintf("%.3f%%", pct)
	} else if pct >= 0.01 {
		return fmt.Sprintf("%.4f%%", pct)
	} else if pct > 0 {
		return fmt.Sprintf("%.6f%%", pct)
	}
	return "0%"
}

func (p *PostgresDB) UpsertPDSRepos(ctx context.Context, endpointID int64, repos []PDSRepoData) error {
	if len(repos) == 0 {
		return nil
	}

	// Step 1: Load all existing repos for this endpoint into memory
	query := `
		SELECT did, head, rev, active, status
		FROM pds_repos
		WHERE endpoint_id = $1
	`

	rows, err := p.db.QueryContext(ctx, query, endpointID)
	if err != nil {
		return err
	}

	existingRepos := make(map[string]*PDSRepo)
	for rows.Next() {
		var repo PDSRepo
		var head, rev, status sql.NullString

		err := rows.Scan(&repo.DID, &head, &rev, &repo.Active, &status)
		if err != nil {
			rows.Close()
			return err
		}

		if head.Valid {
			repo.Head = head.String
		}
		if rev.Valid {
			repo.Rev = rev.String
		}
		if status.Valid {
			repo.Status = status.String
		}

		existingRepos[repo.DID] = &repo
	}
	rows.Close()

	if err := rows.Err(); err != nil {
		return err
	}

	// Step 2: Compare and collect changes
	var newRepos []PDSRepoData
	var changedRepos []PDSRepoData

	for _, repo := range repos {
		existing, exists := existingRepos[repo.DID]
		if !exists {
			// New repo
			newRepos = append(newRepos, repo)
		} else if existing.Head != repo.Head ||
			existing.Rev != repo.Rev ||
			existing.Active != repo.Active ||
			existing.Status != repo.Status {
			// Repo changed
			changedRepos = append(changedRepos, repo)
		}
	}

	// Log comparison results
	log.Verbose("UpsertPDSRepos: endpoint_id=%d, total=%d, existing=%d, new=%d, changed=%d, unchanged=%d",
		endpointID, len(repos), len(existingRepos), len(newRepos), len(changedRepos),
		len(repos)-len(newRepos)-len(changedRepos))

	// If nothing changed, return early
	if len(newRepos) == 0 && len(changedRepos) == 0 {
		log.Verbose("UpsertPDSRepos: endpoint_id=%d, no changes detected, skipping database operations", endpointID)
		return nil
	}

	// Step 3: Execute batched operations
	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Insert new repos
	if len(newRepos) > 0 {
		_, err := tx.Exec(ctx, `
			CREATE TEMP TABLE temp_new_repos (
				did TEXT,
				head TEXT,
				rev TEXT,
				active BOOLEAN,
				status TEXT
			) ON COMMIT DROP
		`)
		if err != nil {
			return err
		}

		_, err = tx.Conn().CopyFrom(
			ctx,
			pgx.Identifier{"temp_new_repos"},
			[]string{"did", "head", "rev", "active", "status"},
			pgx.CopyFromSlice(len(newRepos), func(i int) ([]interface{}, error) {
				repo := newRepos[i]
				return []interface{}{repo.DID, repo.Head, repo.Rev, repo.Active, repo.Status}, nil
			}),
		)
		if err != nil {
			return err
		}

		result, err := tx.Exec(ctx, `
			INSERT INTO pds_repos (endpoint_id, did, head, rev, active, status, first_seen, last_seen)
			SELECT $1, did, head, rev, active, status, 
			       TIMEZONE('UTC', NOW()), 
			       TIMEZONE('UTC', NOW())
			FROM temp_new_repos
		`, endpointID)
		if err != nil {
			return err
		}

		log.Verbose("UpsertPDSRepos: endpoint_id=%d, inserted %d new repos", endpointID, result.RowsAffected())
	}

	// Update changed repos
	if len(changedRepos) > 0 {
		_, err := tx.Exec(ctx, `
			CREATE TEMP TABLE temp_changed_repos (
				did TEXT,
				head TEXT,
				rev TEXT,
				active BOOLEAN,
				status TEXT
			) ON COMMIT DROP
		`)
		if err != nil {
			return err
		}

		_, err = tx.Conn().CopyFrom(
			ctx,
			pgx.Identifier{"temp_changed_repos"},
			[]string{"did", "head", "rev", "active", "status"},
			pgx.CopyFromSlice(len(changedRepos), func(i int) ([]interface{}, error) {
				repo := changedRepos[i]
				return []interface{}{repo.DID, repo.Head, repo.Rev, repo.Active, repo.Status}, nil
			}),
		)
		if err != nil {
			return err
		}

		result, err := tx.Exec(ctx, `
			UPDATE pds_repos
			SET head = t.head,
				rev = t.rev,
				active = t.active,
				status = t.status,
				last_seen = TIMEZONE('UTC', NOW()),
				updated_at = TIMEZONE('UTC', NOW())
			FROM temp_changed_repos t
			WHERE pds_repos.endpoint_id = $1
			  AND pds_repos.did = t.did
		`, endpointID)
		if err != nil {
			return err
		}

		log.Verbose("UpsertPDSRepos: endpoint_id=%d, updated %d changed repos", endpointID, result.RowsAffected())
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}

	log.Verbose("UpsertPDSRepos: endpoint_id=%d, transaction committed successfully", endpointID)
	return nil
}

func (p *PostgresDB) GetPDSRepos(ctx context.Context, endpointID int64, activeOnly bool, limit int, offset int) ([]*PDSRepo, error) {
	query := `
		SELECT id, endpoint_id, did, head, rev, active, status, first_seen, last_seen, updated_at
		FROM pds_repos
		WHERE endpoint_id = $1
	`

	args := []interface{}{endpointID}
	argIdx := 2

	if activeOnly {
		query += " AND active = true"
	}

	// Order by id (primary key) - fastest
	query += " ORDER BY id DESC"

	if limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
		args = append(args, limit, offset)
	}

	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var repos []*PDSRepo
	for rows.Next() {
		var repo PDSRepo
		var head, rev, status sql.NullString

		err := rows.Scan(
			&repo.ID, &repo.EndpointID, &repo.DID, &head, &rev,
			&repo.Active, &status, &repo.FirstSeen, &repo.LastSeen, &repo.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		if head.Valid {
			repo.Head = head.String
		}
		if rev.Valid {
			repo.Rev = rev.String
		}
		if status.Valid {
			repo.Status = status.String
		}

		repos = append(repos, &repo)
	}

	return repos, rows.Err()
}

func (p *PostgresDB) GetReposByDID(ctx context.Context, did string) ([]*PDSRepo, error) {
	query := `
		SELECT id, endpoint_id, did, head, rev, active, status, first_seen, last_seen, updated_at
		FROM pds_repos
		WHERE did = $1
		ORDER BY last_seen DESC
	`

	rows, err := p.db.QueryContext(ctx, query, did)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var repos []*PDSRepo
	for rows.Next() {
		var repo PDSRepo
		var head, rev, status sql.NullString

		err := rows.Scan(
			&repo.ID, &repo.EndpointID, &repo.DID, &head, &rev,
			&repo.Active, &status, &repo.FirstSeen, &repo.LastSeen, &repo.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		if head.Valid {
			repo.Head = head.String
		}
		if rev.Valid {
			repo.Rev = rev.String
		}
		if status.Valid {
			repo.Status = status.String
		}

		repos = append(repos, &repo)
	}

	return repos, rows.Err()
}

func (p *PostgresDB) GetPDSRepoStats(ctx context.Context, endpointID int64) (map[string]interface{}, error) {
	query := `
		SELECT 
			COUNT(*) as total_repos,
			COUNT(*) FILTER (WHERE active = true) as active_repos,
			COUNT(*) FILTER (WHERE active = false) as inactive_repos,
			COUNT(*) FILTER (WHERE status IS NOT NULL AND status != '') as repos_with_status,
			COUNT(*) FILTER (WHERE updated_at > CURRENT_TIMESTAMP - INTERVAL '1 hour') as recent_changes
		FROM pds_repos
		WHERE endpoint_id = $1
	`

	var totalRepos, activeRepos, inactiveRepos, reposWithStatus, recentChanges int64

	err := p.db.QueryRowContext(ctx, query, endpointID).Scan(
		&totalRepos, &activeRepos, &inactiveRepos, &reposWithStatus, &recentChanges,
	)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"total_repos":       totalRepos,
		"active_repos":      activeRepos,
		"inactive_repos":    inactiveRepos,
		"repos_with_status": reposWithStatus,
		"recent_changes":    recentChanges,
	}, nil
}

// GetTableSizes fetches size information (in bytes) for all tables in the specified schema.
func (p *PostgresDB) GetTableSizes(ctx context.Context, schema string) ([]TableSizeInfo, error) {
	// Query now selects raw byte values directly
	query := `
		SELECT
			c.relname AS table_name,
			pg_total_relation_size(c.oid) AS total_bytes,
			pg_relation_size(c.oid) AS table_heap_bytes,
			pg_indexes_size(c.oid) AS indexes_bytes
		FROM
			pg_class c
		LEFT JOIN
			pg_namespace n ON n.oid = c.relnamespace
		WHERE
			c.relkind = 'r' -- 'r' = ordinary table
			AND n.nspname = $1
		ORDER BY
			total_bytes DESC;
	`
	rows, err := p.db.QueryContext(ctx, query, schema)
	if err != nil {
		return nil, fmt.Errorf("failed to query table sizes: %w", err)
	}
	defer rows.Close()

	var results []TableSizeInfo
	for rows.Next() {
		var info TableSizeInfo
		// Scan directly into int64 fields
		if err := rows.Scan(
			&info.TableName,
			&info.TotalBytes,
			&info.TableHeapBytes,
			&info.IndexesBytes,
		); err != nil {
			return nil, fmt.Errorf("failed to scan table size row: %w", err)
		}
		results = append(results, info)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating table size rows: %w", err)
	}

	return results, nil
}

// GetIndexSizes fetches size information (in bytes) for all indexes in the specified schema.
func (p *PostgresDB) GetIndexSizes(ctx context.Context, schema string) ([]IndexSizeInfo, error) {
	// Query now selects raw byte values directly
	query := `
		SELECT
			c.relname AS index_name,
			COALESCE(i.indrelid::regclass::text, 'N/A') AS table_name,
			pg_relation_size(c.oid) AS index_bytes
		FROM
			pg_class c
		LEFT JOIN
			pg_index i ON i.indexrelid = c.oid
		LEFT JOIN
			pg_namespace n ON n.oid = c.relnamespace
		WHERE
			c.relkind = 'i' -- 'i' = index
			AND n.nspname = $1
		ORDER BY
			index_bytes DESC;
	`
	rows, err := p.db.QueryContext(ctx, query, schema)
	if err != nil {
		return nil, fmt.Errorf("failed to query index sizes: %w", err)
	}
	defer rows.Close()

	var results []IndexSizeInfo
	for rows.Next() {
		var info IndexSizeInfo
		var tableName sql.NullString
		// Scan directly into int64 field
		if err := rows.Scan(
			&info.IndexName,
			&tableName,
			&info.IndexBytes,
		); err != nil {
			return nil, fmt.Errorf("failed to scan index size row: %w", err)
		}
		if tableName.Valid {
			info.TableName = tableName.String
		} else {
			info.TableName = "N/A"
		}
		results = append(results, info)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating index size rows: %w", err)
	}

	return results, nil
}
