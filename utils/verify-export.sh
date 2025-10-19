#!/bin/bash
# verify-export.sh - Verify local PLC export endpoint against multiple remotes
# Usage: ./verify-export.sh [after_timestamp] [count]

AFTER="${1:-}"
COUNT="${2:-1000}"
LOCAL_URL="http://localhost:8080/api/v1/plc/export"

# Remote URLs (one per line: "name|url")
REMOTES=(
    "plc.directory|https://plc.directory/export"
    "plc.wtf|https://plc.wtf/export"
)

echo "=== PLC Export Verification ==="
echo "Count: $COUNT"
if [ -n "$AFTER" ]; then
    echo "After: $AFTER"
else
    echo "After: (none - from beginning)"
fi
echo ""

# Build query parameters
PARAMS="count=$COUNT"
if [ -n "$AFTER" ]; then
    PARAMS="${PARAMS}&after=${AFTER}"
fi

# Fetch from local
echo "Fetching from local API..."
echo "curl -s \"${LOCAL_URL}?${PARAMS}\""
LOCAL_DATA=$(curl -s "${LOCAL_URL}?${PARAMS}")
LOCAL_COUNT=$(echo "$LOCAL_DATA" | wc -l | tr -d ' ')
LOCAL_HASH=$(echo "$LOCAL_DATA" | shasum -a 256 | cut -d' ' -f1)

echo "  Operations: $LOCAL_COUNT"
echo "  Hash: $LOCAL_HASH"
echo ""

# Arrays to store remote data
REMOTE_NAMES=()
REMOTE_URLS=()
REMOTE_DATA_ARR=()
REMOTE_COUNT_ARR=()
REMOTE_HASH_ARR=()

# Fetch from all remotes
for i in "${!REMOTES[@]}"; do
    IFS='|' read -r name url <<< "${REMOTES[$i]}"
    
    echo "Fetching from ${name}..."
    echo "curl -s \"${url}?${PARAMS}\""
    
    data=$(curl -s "${url}?${PARAMS}")
    count=$(echo "$data" | wc -l | tr -d ' ')
    hash=$(echo "$data" | shasum -a 256 | cut -d' ' -f1)
    
    REMOTE_NAMES+=("$name")
    REMOTE_URLS+=("$url")
    REMOTE_DATA_ARR+=("$data")
    REMOTE_COUNT_ARR+=("$count")
    REMOTE_HASH_ARR+=("$hash")
    
    echo "  Operations: $count"
    echo "  Hash: $hash"
    echo ""
done

# Compare
echo "=== COMPARISON ==="

# Check local vs each remote
ALL_MATCH=true
MATCHES=()
for i in "${!REMOTE_NAMES[@]}"; do
    name="${REMOTE_NAMES[$i]}"
    hash="${REMOTE_HASH_ARR[$i]}"
    
    if [ "$LOCAL_HASH" = "$hash" ]; then
        echo "Local vs ${name}: ✅ MATCH"
        MATCHES+=("true")
    else
        echo "Local vs ${name}: ❌ MISMATCH"
        MATCHES+=("false")
        ALL_MATCH=false
    fi
done

echo ""

# Check remotes against each other
REMOTES_MATCH=true
if [ ${#REMOTE_NAMES[@]} -gt 1 ]; then
    for ((i=0; i<${#REMOTE_NAMES[@]}-1; i++)); do
        for ((j=i+1; j<${#REMOTE_NAMES[@]}; j++)); do
            name1="${REMOTE_NAMES[$i]}"
            name2="${REMOTE_NAMES[$j]}"
            hash1="${REMOTE_HASH_ARR[$i]}"
            hash2="${REMOTE_HASH_ARR[$j]}"
            
            if [ "$hash1" = "$hash2" ]; then
                echo "${name1} vs ${name2}: ✅ MATCH"
            else
                echo "${name1} vs ${name2}: ❌ MISMATCH"
                REMOTES_MATCH=false
            fi
        done
    done
    echo ""
fi

if [ "$ALL_MATCH" = "true" ]; then
    echo "🎉 ALL MATCH! All endpoints are in perfect sync! 🎯"
    exit 0
else
    echo "❌ DISCREPANCIES DETECTED"
    echo ""
    
    # Show counts comparison
    echo "=== OPERATION COUNTS ==="
    echo "Local: $LOCAL_COUNT operations"
    for i in "${!REMOTE_NAMES[@]}"; do
        name="${REMOTE_NAMES[$i]}"
        count="${REMOTE_COUNT_ARR[$i]}"
        diff=$((count - LOCAL_COUNT))
        echo "${name}: ${count} operations (diff: ${diff})"
    done
    echo ""
    
    # Sample operations from each source
    echo "=== FIRST OPERATIONS ==="
    echo "Local:"
    echo "$LOCAL_DATA" | head -1 | jq -r '[.did, .cid, .createdAt] | @tsv' 2>/dev/null || echo "(parse error)"
    echo ""
    
    for i in "${!REMOTE_NAMES[@]}"; do
        name="${REMOTE_NAMES[$i]}"
        data="${REMOTE_DATA_ARR[$i]}"
        echo "${name}:"
        echo "$data" | head -1 | jq -r '[.did, .cid, .createdAt] | @tsv' 2>/dev/null || echo "(parse error)"
        echo ""
    done
    
    echo "=== LAST OPERATIONS ==="
    echo "Local:"
    echo "$LOCAL_DATA" | tail -1 | jq -r '[.did, .cid, .createdAt] | @tsv' 2>/dev/null || echo "(parse error)"
    echo ""
    
    for i in "${!REMOTE_NAMES[@]}"; do
        name="${REMOTE_NAMES[$i]}"
        data="${REMOTE_DATA_ARR[$i]}"
        echo "${name}:"
        echo "$data" | tail -1 | jq -r '[.did, .cid, .createdAt] | @tsv' 2>/dev/null || echo "(parse error)"
        echo ""
    done
    
    # Find first differences for mismatches
    for i in "${!REMOTE_NAMES[@]}"; do
        if [ "${MATCHES[$i]}" = "false" ]; then
            name="${REMOTE_NAMES[$i]}"
            data="${REMOTE_DATA_ARR[$i]}"
            echo "=== FIRST DIFFERENCES (Local vs ${name}) ==="
            diff <(echo "$LOCAL_DATA" | jq -r '.cid' 2>/dev/null | head -20) \
                 <(echo "$data" | jq -r '.cid' 2>/dev/null | head -20) || true
            echo ""
        fi
    done
    
    # Check differences between remotes
    if [ "$REMOTES_MATCH" = "false" ] && [ ${#REMOTE_NAMES[@]} -gt 1 ]; then
        for ((i=0; i<${#REMOTE_NAMES[@]}-1; i++)); do
            for ((j=i+1; j<${#REMOTE_NAMES[@]}; j++)); do
                name1="${REMOTE_NAMES[$i]}"
                name2="${REMOTE_NAMES[$j]}"
                hash1="${REMOTE_HASH_ARR[$i]}"
                hash2="${REMOTE_HASH_ARR[$j]}"
                
                if [ "$hash1" != "$hash2" ]; then
                    data1="${REMOTE_DATA_ARR[$i]}"
                    data2="${REMOTE_DATA_ARR[$j]}"
                    echo "=== FIRST DIFFERENCES (${name1} vs ${name2}) ==="
                    diff <(echo "$data1" | jq -r '.cid' 2>/dev/null | head -20) \
                         <(echo "$data2" | jq -r '.cid' 2>/dev/null | head -20) || true
                    echo ""
                fi
            done
        done
    fi
    
    exit 1
fi

