#!/bin/bash
# verify-export.sh - Verify local PLC export endpoint against plc.directory
# Usage: ./verify-export.sh [after_timestamp] [count]

AFTER="${1:-}"
COUNT="${2:-50}"
LOCAL_URL="http://localhost:8080/api/v1/plc/export"
REMOTE_URL="https://plc.directory/export"

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

echo "Fetching from local API..."
echo "curl -s \"${LOCAL_URL}?${PARAMS}\""
LOCAL_DATA=$(curl -s "${LOCAL_URL}?${PARAMS}")
LOCAL_COUNT=$(echo "$LOCAL_DATA" | wc -l | tr -d ' ')
LOCAL_HASH=$(echo "$LOCAL_DATA" | shasum -a 256 | cut -d' ' -f1)

echo "  Operations: $LOCAL_COUNT"
echo "  Hash: $LOCAL_HASH"
echo ""

echo "Fetching from plc.directory..."
REMOTE_DATA=$(curl -s "${REMOTE_URL}?${PARAMS}")
REMOTE_COUNT=$(echo "$REMOTE_DATA" | wc -l | tr -d ' ')
REMOTE_HASH=$(echo "$REMOTE_DATA" | shasum -a 256 | cut -d' ' -f1)

echo "  Operations: $REMOTE_COUNT"
echo "  Hash: $REMOTE_HASH"
echo ""

# Compare
echo "=== COMPARISON ==="
if [ "$LOCAL_HASH" = "$REMOTE_HASH" ]; then
    echo "✅ MATCH! Hashes are identical"
    echo ""
    echo "Local and remote exports are in sync! 🎯"
    exit 0
else
    echo "❌ MISMATCH! Hashes differ"
    echo ""
    
    # Show counts
    if [ "$LOCAL_COUNT" != "$REMOTE_COUNT" ]; then
        echo "⚠️  Operation count differs:"
        echo "   Local:  $LOCAL_COUNT operations"
        echo "   Remote: $REMOTE_COUNT operations"
        echo "   Diff:   $((REMOTE_COUNT - LOCAL_COUNT))"
        echo ""
    fi
    
    # Sample first and last operations
    echo "First operation (local):"
    echo "$LOCAL_DATA" | head -1 | jq -r '[.did, .cid, .createdAt] | @tsv' 2>/dev/null || echo "(parse error)"
    echo ""
    
    echo "First operation (remote):"
    echo "$REMOTE_DATA" | head -1 | jq -r '[.did, .cid, .createdAt] | @tsv' 2>/dev/null || echo "(parse error)"
    echo ""
    
    echo "Last operation (local):"
    echo "$LOCAL_DATA" | tail -1 | jq -r '[.did, .cid, .createdAt] | @tsv' 2>/dev/null || echo "(parse error)"
    echo ""
    
    echo "Last operation (remote):"
    echo "$REMOTE_DATA" | tail -1 | jq -r '[.did, .cid, .createdAt] | @tsv' 2>/dev/null || echo "(parse error)"
    echo ""
    
    # Find first difference
    echo "Finding first difference..."
    diff <(echo "$LOCAL_DATA" | jq -r '.cid' 2>/dev/null | head -20) \
         <(echo "$REMOTE_DATA" | jq -r '.cid' 2>/dev/null | head -20) || true
    
    exit 1
fi

