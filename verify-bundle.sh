#!/bin/bash
# verify-bundle.sh <bundle_number>

BUNDLE_NUM=$1
PLC_DIRECTORIES=("plc.directory" "plc.wtf")

# Fetch bundle hash from local server
if [ "$BUNDLE_NUM" -eq 1 ]; then
    # Bundle 1 - no after parameter
    BUNDLE_HASH=$(curl -s "http://localhost:8080/api/v1/plc/bundles/$BUNDLE_NUM" | jq -r '.hash')
    
    echo "Bundle $BUNDLE_NUM hash: $BUNDLE_HASH"
    echo ""
    
    # Compare with each PLC directory
    ALL_MATCH=true
    for PLC_DIR in "${PLC_DIRECTORIES[@]}"; do
        echo "Checking $PLC_DIR..."
        REMOTE_HASH=$(curl -s "https://$PLC_DIR/export?count=1000" | shasum -a 256 | cut -d' ' -f1)
        echo "  Remote hash: $REMOTE_HASH"
        
        if [ "$BUNDLE_HASH" = "$REMOTE_HASH" ]; then
            echo "  ✅ Verified!"
        else
            echo "  ❌ Hash mismatch!"
            ALL_MATCH=false
        fi
        echo ""
    done
else
    # Bundle N - need previous bundle's end_time
    PREV_NUM=$((BUNDLE_NUM - 1))
    AFTER=$(curl -s "http://localhost:8080/api/v1/plc/bundles/$PREV_NUM" | jq -r '.end_time')
    BUNDLE_HASH=$(curl -s "http://localhost:8080/api/v1/plc/bundles/$BUNDLE_NUM" | jq -r '.hash')
    
    echo "Bundle $BUNDLE_NUM hash: $BUNDLE_HASH"
    echo "Using after parameter: $AFTER"
    echo ""
    
    # Compare with each PLC directory
    ALL_MATCH=true
    for PLC_DIR in "${PLC_DIRECTORIES[@]}"; do
        echo "Checking $PLC_DIR..."
        echo "  curl -s \"https://$PLC_DIR/export?count=1000&after=$AFTER\" | shasum -a 256 | cut -d' ' -f1"
        REMOTE_HASH=$(curl -s "https://$PLC_DIR/export?count=1000&after=$AFTER" | shasum -a 256 | cut -d' ' -f1)
        echo "  Remote hash: $REMOTE_HASH"
        
        if [ "$BUNDLE_HASH" = "$REMOTE_HASH" ]; then
            echo "  ✅ Verified!"
        else
            echo "  ❌ Hash mismatch!"
            ALL_MATCH=false
        fi
        echo ""
    done
fi

# Final result
if [ "$ALL_MATCH" = true ]; then
    echo "✅ All sources verified successfully!"
    exit 0
else
    echo "❌ One or more sources failed verification"
    exit 1
fi

