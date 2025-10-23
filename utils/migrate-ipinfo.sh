#!/bin/bash
# migrate_ipinfo.sh - Migrate IP info from endpoints to ip_infos table

# Configuration (edit these)
DB_HOST="localhost"
DB_PORT="5432"
DB_NAME="atscanner"
DB_USER="atscanner"
DB_PASSWORD="Noor1kooz5eeFai9leZagh5ua5eihai4"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== IP Info Migration Script ===${NC}"
echo ""

# Export password for psql
export PGPASSWORD="$DB_PASSWORD"

# Check if we can connect
echo -e "${YELLOW}Testing database connection...${NC}"
if ! psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1;" > /dev/null 2>&1; then
    echo -e "${RED}Error: Cannot connect to database${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Connected to database${NC}"
echo ""

# Create ip_infos table if it doesn't exist
echo -e "${YELLOW}Creating ip_infos table...${NC}"
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" << 'SQL'
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
    fetched_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ip_infos_country_code ON ip_infos(country_code);
CREATE INDEX IF NOT EXISTS idx_ip_infos_asn ON ip_infos(asn);
SQL

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ ip_infos table ready${NC}"
else
    echo -e "${RED}✗ Failed to create table${NC}"
    exit 1
fi
echo ""

# Count how many endpoints have IP info
echo -e "${YELLOW}Checking existing data...${NC}"
ENDPOINT_COUNT=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c \
    "SELECT COUNT(*) FROM endpoints WHERE ip IS NOT NULL AND ip != '' AND ip_info IS NOT NULL;")
echo -e "Endpoints with IP info: ${GREEN}${ENDPOINT_COUNT}${NC}"

EXISTING_IP_COUNT=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c \
    "SELECT COUNT(*) FROM ip_infos;")
echo -e "Existing IPs in ip_infos table: ${GREEN}${EXISTING_IP_COUNT}${NC}"
echo ""

# Migrate data
echo -e "${YELLOW}Migrating IP info data...${NC}"
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" << 'SQL'
-- Migrate IP info from endpoints to ip_infos
-- Only insert IPs that don't already exist in ip_infos
INSERT INTO ip_infos (
    ip,
    city,
    country,
    country_code,
    asn,
    asn_org,
    is_datacenter,
    is_vpn,
    latitude,
    longitude,
    raw_data,
    fetched_at,
    updated_at
)
SELECT DISTINCT ON (e.ip)
    e.ip,
    e.ip_info->'location'->>'city' AS city,
    e.ip_info->'location'->>'country' AS country,
    e.ip_info->'location'->>'country_code' AS country_code,
    (e.ip_info->'asn'->>'asn')::INTEGER AS asn,
    e.ip_info->'asn'->>'org' AS asn_org,
    -- Check if company type is "hosting" for datacenter detection
    CASE 
        WHEN e.ip_info->'company'->>'type' = 'hosting' THEN true
        ELSE false
    END AS is_datacenter,
    -- Check VPN from security field
    COALESCE((e.ip_info->'security'->>'vpn')::BOOLEAN, false) AS is_vpn,
    -- Latitude and longitude
    (e.ip_info->'location'->>'latitude')::REAL AS latitude,
    (e.ip_info->'location'->>'longitude')::REAL AS longitude,
    -- Store full raw data
    e.ip_info AS raw_data,
    COALESCE(e.updated_at, CURRENT_TIMESTAMP) AS fetched_at,
    CURRENT_TIMESTAMP AS updated_at
FROM endpoints e
WHERE 
    e.ip IS NOT NULL 
    AND e.ip != '' 
    AND e.ip_info IS NOT NULL
    AND NOT EXISTS (
        SELECT 1 FROM ip_infos WHERE ip_infos.ip = e.ip
    )
ORDER BY e.ip, e.updated_at DESC NULLS LAST;
SQL

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Data migration completed${NC}"
else
    echo -e "${RED}✗ Migration failed${NC}"
    exit 1
fi
echo ""

# Show results
echo -e "${YELLOW}Migration summary:${NC}"
NEW_IP_COUNT=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c \
    "SELECT COUNT(*) FROM ip_infos;")
MIGRATED=$((NEW_IP_COUNT - EXISTING_IP_COUNT))
echo -e "Total IPs now in ip_infos: ${GREEN}${NEW_IP_COUNT}${NC}"
echo -e "Newly migrated: ${GREEN}${MIGRATED}${NC}"
echo ""

# Show sample data
echo -e "${YELLOW}Sample migrated data:${NC}"
psql -h "$DB_HOST" -ps "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c \
    "SELECT ip, city, country, country_code, asn, is_datacenter, is_vpn FROM ip_infos LIMIT 5;"
echo ""

# Optional: Drop old columns (commented out for safety)
echo -e "${YELLOW}Cleanup options:${NC}"
echo -e "To remove old ip_info column from endpoints table, run:"
echo -e "${RED}  ALTER TABLE endpoints DROP COLUMN IF EXISTS ip_info;${NC}"
echo -e "To remove old user_count column from endpoints table, run:"
echo -e "${RED}  ALTER TABLE endpoints DROP COLUMN IF EXISTS user_count;${NC}"
echo ""

echo -e "${GREEN}=== Migration Complete ===${NC}"

# Unset password
unset PGPASSWORD
