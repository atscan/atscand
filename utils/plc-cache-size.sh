#!/bin/sh
total_uncompressed_size=0
for file in plc_cache/*.zst; do
  uncompressed_size=$(zstd -l "$file" | awk '/Decompressed Size/ {print $3}')
  total_uncompressed_size=$((total_uncompressed_size + uncompressed_size))
done
echo "Total uncompressed size: $total_uncompressed_size Bytes"
