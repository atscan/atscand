#!/bin/bash
# verify-export-debug.sh - Deep comparison of export endpoints

AFTER="${1:-}"
COUNT="${2:-1000}"
LOCAL_URL="http://localhost:8080/api/v1/plc/export"
REMOTE_URL="https://plc.directory/export"

# Build query parameters
PARAMS="count=$COUNT"
if [ -n "$AFTER" ]; then
    PARAMS="${PARAMS}&after=${AFTER}"
fi

echo "=== Fetching data ==="
curl -s "${LOCAL_URL}?${PARAMS}" > /tmp/local_export.jsonl
curl -s "${REMOTE_URL}?${PARAMS}" > /tmp/remote_export.jsonl

echo "Local file size:  $(wc -c < /tmp/local_export.jsonl) bytes"
echo "Remote file size: $(wc -c < /tmp/remote_export.jsonl) bytes"
echo ""

echo "Local lines:  $(wc -l < /tmp/local_export.jsonl)"
echo "Remote lines: $(wc -l < /tmp/remote_export.jsonl)"
echo ""

# Check for trailing newline
echo "Local ends with newline:  $(tail -c 1 /tmp/local_export.jsonl | xxd -p)"
echo "Remote ends with newline: $(tail -c 1 /tmp/remote_export.jsonl | xxd -p)"
echo "(0a = newline, other = no trailing newline)"
echo ""

# Compare line by line
echo "=== Comparing CIDs line by line ==="
LOCAL_CIDS=$(cat /tmp/local_export.jsonl | jq -r '.cid' 2>/dev/null)
REMOTE_CIDS=$(cat /tmp/remote_export.jsonl | jq -r '.cid' 2>/dev/null)

if [ "$LOCAL_CIDS" = "$REMOTE_CIDS" ]; then
    echo "✅ All CIDs match in order"
else
    echo "❌ CIDs differ"
    echo ""
    echo "First 5 local CIDs:"
    echo "$LOCAL_CIDS" | head -5
    echo ""
    echo "First 5 remote CIDs:"
    echo "$REMOTE_CIDS" | head -5
fi
echo ""

# Compare exact JSON of first operation
echo "=== First operation comparison ==="
echo "Local:"
head -1 /tmp/local_export.jsonl | jq . 2>/dev/null || head -1 /tmp/local_export.jsonl
echo ""
echo "Remote:"
head -1 /tmp/remote_export.jsonl | jq . 2>/dev/null || head -1 /tmp/remote_export.jsonl
echo ""

# Check if it's just a trailing newline issue
echo "=== Testing trailing newline hypothesis ==="
LOCAL_HASH_NO_TRAIL=$(head -c -1 /tmp/local_export.jsonl | shasum -a 256 | cut -d' ' -f1)
REMOTE_HASH_NO_TRAIL=$(head -c -1 /tmp/remote_export.jsonl | shasum -a 256 | cut -d' ' -f1)

LOCAL_HASH_WITH_TRAIL=$(cat /tmp/local_export.jsonl && echo "" | shasum -a 256 | cut -d' ' -f1)

echo "Local hash (as-is):           $(shasum -a 256 < /tmp/local_export.jsonl | cut -d' ' -f1)"
echo "Remote hash (as-is):          $(shasum -a 256 < /tmp/remote_export.jsonl | cut -d' ' -f1)"
echo "Local hash (no trailing \\n):  $LOCAL_HASH_NO_TRAIL"
echo "Remote hash (no trailing \\n): $REMOTE_HASH_NO_TRAIL"

if [ "$LOCAL_HASH_NO_TRAIL" = "$(shasum -a 256 < /tmp/remote_export.jsonl | cut -d' ' -f1)" ]; then
    echo ""
    echo "🔍 Found it! Local is missing trailing newline"
elif [ "$(shasum -a 256 < /tmp/local_export.jsonl | cut -d' ' -f1)" = "$REMOTE_HASH_NO_TRAIL" ]; then
    echo ""
    echo "🔍 Found it! Remote is missing trailing newline"
fi

# Clean up
rm -f /tmp/local_export.jsonl /tmp/remote_export.jsonl

