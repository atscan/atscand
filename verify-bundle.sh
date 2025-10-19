#!/bin/bash
# verify-bundle.sh <bundle_number>

BUNDLE_NUM=$1

if [ "$BUNDLE_NUM" -eq 1 ]; then
    # Bundle 1 - no after parameter
    BUNDLE_HASH=$(curl -s "http://localhost:8080/api/v1/plc/bundles/$BUNDLE_NUM" | jq -r '.hash')
    REMOTE_HASH=$(curl -s 'https://plc.directory/export?count=1000' | shasum -a 256 | cut -d' ' -f1)
else
    # Bundle N - need previous bundle's end_time
    PREV_NUM=$((BUNDLE_NUM - 1))
    AFTER=$(curl -s "http://localhost:8080/api/v1/plc/bundles/$PREV_NUM" | jq -r '.end_time')
    BUNDLE_HASH=$(curl -s "http://localhost:8080/api/v1/plc/bundles/$BUNDLE_NUM" | jq -r '.hash')
    REMOTE_HASH=$(curl -s "https://plc.directory/export?count=1000&after=$AFTER" | shasum -a 256 | cut -d' ' -f1)
fi

echo "Bundle $BUNDLE_NUM hash: $BUNDLE_HASH"
echo "Remote hash: $REMOTE_HASH"

if [ "$BUNDLE_HASH" = "$REMOTE_HASH" ]; then
    echo "✅ Verified!"
    exit 0
else
    echo "❌ Hash mismatch!"
    exit 1
fi
