#!/bin/bash

# Configuration
API_HOST="${API_HOST:-http://localhost:8080}"
TIMEOUT=5
OUTPUT_DIR="./pds_scan_results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_FILE="${OUTPUT_DIR}/scan_${TIMESTAMP}.txt"
FOUND_FILE="${OUTPUT_DIR}/found_${TIMESTAMP}.txt"

# Paths to check (one per line for easier editing)
PATHS=(
    "/info.php"
    "/phpinfo.php"
    "/test.php"
    "/admin"
    "/admin.php"
    "/wp-admin"
    "/robots.txt"
    "/.env"
    "/.git/config"
    "/config.php"
    "/backup"
    "/db.sql"
    "/.DS_Store"
    "/server-status"
    "/.well-known/security.txt"
)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

mkdir -p "$OUTPUT_DIR"

echo -e "${BLUE}=== PDS Security Scanner ===${NC}"
echo "API Host: $API_HOST"
echo "Timeout: ${TIMEOUT}s"
echo "Scanning for ${#PATHS[@]} paths"
echo "Results: $RESULTS_FILE"
echo ""

# Fetch active PDS endpoints
echo -e "${YELLOW}Fetching active PDS endpoints...${NC}"
ENDPOINTS=$(curl -s "${API_HOST}/api/v1/pds?status=online&limit=10000" | \
    jq -r '.[].endpoint' 2>/dev/null)

if [ -z "$ENDPOINTS" ]; then
    echo -e "${RED}Error: Could not fetch endpoints from API${NC}"
    exit 1
fi

ENDPOINT_COUNT=$(echo "$ENDPOINTS" | wc -l)
echo -e "${GREEN}Found ${ENDPOINT_COUNT} active PDS endpoints${NC}"
echo ""

# Write header
echo "PDS Security Scan - $(date)" > "$RESULTS_FILE"
echo "========================================" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

# Counters
CURRENT=0
TOTAL_FOUND=0
TOTAL_MAYBE=0

# Scan each endpoint sequentially
while IFS= read -r endpoint; do
    CURRENT=$((CURRENT + 1))
    
    echo -e "${BLUE}[$CURRENT/$ENDPOINT_COUNT]${NC} Scanning: $endpoint"
    
    # Scan each path
    for path in "${PATHS[@]}"; do
        url="${endpoint}${path}"
        
        # Make request with timeout
        response=$(curl -s -o /dev/null -w "%{http_code}" \
            --max-time "$TIMEOUT" \
            --connect-timeout "$TIMEOUT" \
            -L \
            -A "Mozilla/5.0 (Security Scanner)" \
            "$url" 2>/dev/null)
        
        # Check response
        if [ -n "$response" ] && [ "$response" != "404" ] && [ "$response" != "000" ]; then
            if [ "$response" = "200" ] || [ "$response" = "301" ] || [ "$response" = "302" ]; then
                echo -e "  ${GREEN}✓ FOUND${NC} $path ${YELLOW}[$response]${NC}"
                echo "FOUND: $endpoint$path [$response]" >> "$RESULTS_FILE"
                echo "$endpoint$path" >> "$FOUND_FILE"
                TOTAL_FOUND=$((TOTAL_FOUND + 1))
            elif [ "$response" != "403" ]; then
                echo -e "  ${YELLOW}? MAYBE${NC} $path ${YELLOW}[$response]${NC}"
                echo "MAYBE: $endpoint$path [$response]" >> "$RESULTS_FILE"
                TOTAL_MAYBE=$((TOTAL_MAYBE + 1))
            fi
        fi
    done
    
    echo "" >> "$RESULTS_FILE"
    
done <<< "$ENDPOINTS"

# Summary
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}Scan Complete!${NC}"
echo "Scanned: ${ENDPOINT_COUNT} endpoints"
echo "Paths checked per endpoint: ${#PATHS[@]}"
echo -e "${GREEN}Found (200/301/302): ${TOTAL_FOUND}${NC}"
echo -e "${YELLOW}Maybe (other codes): ${TOTAL_MAYBE}${NC}"
echo ""
echo "Full results: $RESULTS_FILE"
[ -f "$FOUND_FILE" ] && echo "Found URLs: $FOUND_FILE"
