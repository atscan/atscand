#!/bin/bash

# === Configuration ===
CONFIG_FILE="config.yaml" # Path to your config file
SCHEMA_NAME="public"      # Replace if your schema is different

# Check if config file exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: Config file not found at '$CONFIG_FILE'"
    exit 1
fi

# Check if yq is installed
if ! command -v yq &> /dev/null; then
    echo "Error: 'yq' command not found. Please install yq (Go version by Mike Farah)."
    echo "See: https://github.com/mikefarah/yq/"
    exit 1
fi

echo "--- Reading connection info from '$CONFIG_FILE' ---"

# === Extract Database Config using yq ===
DB_TYPE=$(yq e '.database.type' "$CONFIG_FILE")
DB_CONN_STRING=$(yq e '.database.path' "$CONFIG_FILE") # This is likely a URI

if [ -z "$DB_TYPE" ] || [ -z "$DB_CONN_STRING" ]; then
    echo "Error: Could not read database type or path from '$CONFIG_FILE'."
    exit 1
fi

# === Parse the Connection String ===
DB_USER=""
DB_PASSWORD=""
DB_HOST="localhost" # Default
DB_PORT="5432"      # Default
DB_NAME=""

# Use regex to parse the URI (handles postgres:// or postgresql://, optional password/port, and query parameters)
if [[ "$DB_CONN_STRING" =~ ^(postgres|postgresql)://([^:]+)(:([^@]+))?@([^:/]+)(:([0-9]+))?/([^?]+)(\?.+)?$ ]]; then
    DB_USER="${BASH_REMATCH[2]}"
    DB_PASSWORD="${BASH_REMATCH[4]}" # Optional group
    DB_HOST="${BASH_REMATCH[5]}"
    DB_PORT="${BASH_REMATCH[7]:-$DB_PORT}" # Use extracted port or default
    DB_NAME="${BASH_REMATCH[8]}" # Database name before the '?'
else
    echo "Error: Could not parse database connection string URI: $DB_CONN_STRING"
    exit 1
fi

# Set PGPASSWORD environment variable if password was found
if [ -n "$DB_PASSWORD" ]; then
    export PGPASSWORD="$DB_PASSWORD"
else
    echo "Warning: No password found in connection string. Relying on ~/.pgpass or password prompt."
    unset PGPASSWORD
fi

echo "--- Database Size Investigation ---"
echo "Database: $DB_NAME"
echo "Schema:   $SCHEMA_NAME"
echo "User:     $DB_USER"
echo "Host:     $DB_HOST:$DB_PORT"
echo "-----------------------------------"

# === Table Sizes ===
echo ""
echo "## Table Sizes (Schema: $SCHEMA_NAME) ##"
# Removed --tuples-only and --no-align, added -P footer=off
psql -U "$DB_USER" -d "$DB_NAME" -h "$DB_HOST" -p "$DB_PORT" -X -q -P footer=off <<EOF
SELECT
    c.relname AS "Table Name",
    pg_size_pretty(pg_total_relation_size(c.oid)) AS "Total Size",
    pg_size_pretty(pg_relation_size(c.oid)) AS "Table Heap Size",
    pg_size_pretty(pg_indexes_size(c.oid)) AS "Indexes Size"
FROM
    pg_class c
LEFT JOIN
    pg_namespace n ON n.oid = c.relnamespace
WHERE
    c.relkind = 'r' -- 'r' = ordinary table
    AND n.nspname = '$SCHEMA_NAME'
ORDER BY
    pg_total_relation_size(c.oid) DESC;
EOF

if [ $? -ne 0 ]; then
    echo "Error querying table sizes. Check connection details, permissions, and password."
    unset PGPASSWORD
    exit 1
fi

# === Index Sizes ===
echo ""
echo "## Index Sizes (Schema: $SCHEMA_NAME) ##"
# Removed --tuples-only and --no-align, added -P footer=off
psql -U "$DB_USER" -d "$DB_NAME" -h "$DB_HOST" -p "$DB_PORT" -X -q -P footer=off <<EOF
SELECT
    c.relname AS "Index Name",
    i.indrelid::regclass AS "Table Name", -- Show associated table
    pg_size_pretty(pg_relation_size(c.oid)) AS "Index Size"
FROM
    pg_class c
LEFT JOIN
    pg_index i ON i.indexrelid = c.oid
LEFT JOIN
    pg_namespace n ON n.oid = c.relnamespace
WHERE
    c.relkind = 'i' -- 'i' = index
    AND n.nspname = '$SCHEMA_NAME'
ORDER BY
    pg_relation_size(c.oid) DESC;
EOF

if [ $? -ne 0 ]; then
    echo "Error querying index sizes. Check connection details, permissions, and password."
    unset PGPASSWORD
    exit 1
fi

echo ""
echo "-----------------------------------"
echo "Investigation complete."

# Unset the password variable for security
unset PGPASSWORD