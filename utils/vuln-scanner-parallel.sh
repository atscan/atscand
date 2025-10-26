#!/bin/bash

# Configuration
API_HOST="${API_HOST:-http://localhost:8080}"
TIMEOUT=5
PARALLEL_JOBS=20
OUTPUT_DIR="./pds_scan_results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_FILE="${OUTPUT_DIR}/scan_${TIMESTAMP}.txt"
FOUND_FILE="${OUTPUT_DIR}/found_${TIMESTAMP}.txt"

# Paths to check
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

# Check dependencies
if ! command -v jq &> /dev/null; then
    echo -e "${RED}Error: jq is required${NC}"
    echo "Install: sudo apt-get install jq"
    exit 1
fi

if ! command -v parallel &> /dev/null; then
    echo -e "${RED}Error: GNU parallel is required${NC}"
    echo "Install: sudo apt-get install parallel (or brew install parallel)"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   PDS Security Scanner (Parallel)     ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
echo ""
echo "API Host: $API_HOST"
echo "Timeout: ${TIMEOUT}s per request"
echo "Parallel jobs: ${PARALLEL_JOBS}"
echo "Paths to check: ${#PATHS[@]}"
echo ""

# Scan function - will be called by GNU parallel
scan_endpoint() {
    local endpoint="$1"
    local timeout="$2"
    shift 2
    local paths=("$@")
    
    for path in "${paths[@]}"; do
        url="${endpoint}${path}"
        
        response=$(curl -s -o /dev/null -w "%{http_code}" \
            --max-time "$timeout" \
            --connect-timeout "$timeout" \
            --retry 0 \
            -A "Mozilla/5.0 (Security Scanner)" \
            "$url" 2>/dev/null)
        
        if [ -n "$response" ] && [ "$response" != "404" ] && [ "$response" != "000" ]; then
            if [ "$response" = "200" ] || [ "$response" = "301" ] || [ "$response" = "302" ]; then
                echo "FOUND|$endpoint|$path|$response"
            elif [ "$response" != "403" ] && [ "$response" != "401" ]; then
                echo "MAYBE|$endpoint|$path|$response"
            fi
        fi
    done
}

export -f scan_endpoint

# Fetch active PDS endpoints
echo -e "${YELLOW}Fetching active PDS endpoints...${NC}"
ENDPOINTS=$(curl -s "${API_HOST}/api/v1/pds?status=online&limit=10000" | \
    jq -r '.[].endpoint' 2>/dev/null)

if [ -z "$ENDPOINTS" ]; then
    echo -e "${RED}Error: Could not fetch endpoints from API${NC}"
    echo "Check that the API is running at: $API_HOST"
    exit 1
fi

ENDPOINT_COUNT=$(echo "$ENDPOINTS" | wc -l | tr -d ' ')
echo -e "${GREEN}✓ Found ${ENDPOINT_COUNT} active PDS endpoints${NC}"
echo ""

# Write header to results file
{
    echo "PDS Security Scan Results"
    echo "========================="
    echo "Scan started: $(date)"
    echo "Endpoints scanned: ${ENDPOINT_COUNT}"
    echo "Paths checked: ${#PATHS[@]}"
    echo "Parallel jobs: ${PARALLEL_JOBS}"
    echo ""
    echo "Results:"
    echo "--------"
} > "$RESULTS_FILE"

# Run parallel scan
echo -e "${YELLOW}Starting parallel scan...${NC}"
echo -e "${BLUE}(This may take a few minutes depending on endpoint count)${NC}"
echo ""

echo "$ENDPOINTS" | \
    parallel \
        -j "$PARALLEL_JOBS" \
        --bar \
        --joblog "${OUTPUT_DIR}/joblog_${TIMESTAMP}.txt" \
        scan_endpoint {} "$TIMEOUT" "${PATHS[@]}" \
    >> "$RESULTS_FILE"

echo ""
echo -e "${YELLOW}Processing results...${NC}"

# Count results
FOUND_COUNT=$(grep -c "^FOUND|" "$RESULTS_FILE" 2>/dev/null || echo 0)
MAYBE_COUNT=$(grep -c "^MAYBE|" "$RESULTS_FILE" 2>/dev/null || echo 0)

# Extract found URLs to separate file
{
    echo "Found URLs (HTTP 200/301/302)"
    echo "=============================="
    echo "Scan: $(date)"
    echo ""
} > "$FOUND_FILE"

grep "^FOUND|" "$RESULTS_FILE" 2>/dev/null | while IFS='|' read -r status endpoint path code; do
    echo "$endpoint$path [$code]"
done >> "$FOUND_FILE"

# Create summary at end of results file
{
    echo ""
    echo "Summary"
    echo "======="
    echo "Scan completed: $(date)"
    echo "Total endpoints scanned: ${ENDPOINT_COUNT}"
    echo "Total paths checked: $((ENDPOINT_COUNT * ${#PATHS[@]}))"
    echo "Found (200/301/302): ${FOUND_COUNT}"
    echo "Maybe (other codes): ${MAYBE_COUNT}"
} >> "$RESULTS_FILE"

# Display summary
echo ""
echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║            Scan Complete!              ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
echo ""
echo -e "Endpoints scanned:        ${GREEN}${ENDPOINT_COUNT}${NC}"
echo -e "Paths checked per site:   ${BLUE}${#PATHS[@]}${NC}"
echo -e "Total requests made:      ${BLUE}$((ENDPOINT_COUNT * ${#PATHS[@]}))${NC}"
echo ""
echo -e "Results:"
echo -e "  ${GREEN}✓ Found (200/301/302):${NC}  ${FOUND_COUNT}"
echo -e "  ${YELLOW}? Maybe (other):${NC}       ${MAYBE_COUNT}"
echo ""
echo "Files created:"
echo "  Full results:  $RESULTS_FILE"
echo "  Found URLs:    $FOUND_FILE"
echo "  Job log:       ${OUTPUT_DIR}/joblog_${TIMESTAMP}.txt"

# Show sample of found URLs if any
if [ "$FOUND_COUNT" -gt 0 ]; then
    echo ""
    echo -e "${RED}⚠ SECURITY ALERT: Found exposed paths!${NC}"
    echo ""
    echo "Sample findings (first 10):"
    grep "^FOUND|" "$RESULTS_FILE" 2>/dev/null | head -10 | while IFS='|' read -r status endpoint path code; do
        echo -e "  ${RED}✗${NC} $endpoint${RED}$path${NC} [$code]"
    done
    
    if [ "$FOUND_COUNT" -gt 10 ]; then
        echo ""
        echo "  ... and $((FOUND_COUNT - 10)) more (see $FOUND_FILE)"
    fi
fi

echo ""
