#!/bin/bash
# import-labels-v4-sorted-pipe.sh

set -e

if [ $# -lt 1 ]; then
    echo "Usage: ./utils/import-labels-v4-sorted-pipe.sh <csv-file>"
    exit 1
fi

CSV_FILE="$1"
CONFIG_FILE="config.yaml"

[ ! -f "$CSV_FILE" ] && echo "Error: CSV file not found" && exit 1
[ ! -f "$CONFIG_FILE" ] && echo "Error: config.yaml not found" && exit 1

# Extract bundle directory path
BUNDLE_DIR=$(grep -A 5 "^plc:" "$CONFIG_FILE" | grep "bundle_dir:" | sed 's/.*bundle_dir: *"//' | sed 's/".*//' | head -1)

[ -z "$BUNDLE_DIR" ] && echo "Error: Could not parse plc.bundle_dir from config.yaml" && exit 1

FINAL_LABELS_DIR="$BUNDLE_DIR/labels"

echo "========================================"
echo "PLC Operation Labels Import (Sorted Pipe)"
echo "========================================"
echo "CSV File:       $CSV_FILE"
echo "Output Dir:     $FINAL_LABELS_DIR"
echo ""

# Ensure the final directory exists
mkdir -p "$FINAL_LABELS_DIR"

echo "Streaming, sorting, and compressing on the fly..."
echo "This will take time. `pv` will show progress of the TAIL command."
echo "The `sort` command will run after `pv` is complete."
echo ""

# This is the single-pass pipeline
tail -n +2 "$CSV_FILE" | \
    pv -l -s $(tail -n +2 "$CSV_FILE" | wc -l) | \
    sort -t, -k1,1n | \
    awk -F',' -v final_dir="$FINAL_LABELS_DIR" '
    # This awk script EXPECTS input sorted by bundle number (col 1)
    BEGIN {
        # last_bundle_num tracks the bundle we are currently writing
        last_bundle_num = -1
        # cmd holds the current zstd pipe command
        cmd = ""
    }
    {
        current_bundle_num = $1
        
        # Check if the bundle number has changed
        if (current_bundle_num != last_bundle_num) {
            
            # If it changed, and we have an old pipe open, close it
            if (last_bundle_num != -1) {
                close(cmd)
            }
            
            # Create the new pipe command, writing to the final .zst file
            outfile = sprintf("%s/%06d.csv.zst", final_dir, current_bundle_num)
            cmd = "zstd -T0 -o " outfile
            
            # Update the tracker
            last_bundle_num = current_bundle_num
            
            # Print progress to stderr
            printf "  -> Writing bundle %06d\n", current_bundle_num > "/dev/stderr"
        }
        
        # Print the current line ($0) to the open pipe
        # The first time this runs for a bundle, it opens the pipe
        # Subsequent times, it writes to the already-open pipe
        print $0 | cmd
    }
    # END block: close the very last pipe
    END {
        if (last_bundle_num != -1) {
            close(cmd)
        }
        printf "  Finished. Total lines: %d\n", NR > "/dev/stderr"
    }'

echo ""
echo "========================================"
echo "Import Summary"
echo "========================================"
echo "✓ Import completed successfully!"
echo "Label files are stored in: $FINAL_LABELS_DIR"