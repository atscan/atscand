pv plc_bundles/*.jsonl.zst | zstdcat | \
  jq -r '.createdAt' | \
  awk '
    NR > 1 && $0 < prev {
      printf "NOT SORTED at line %d:\n", NR > "/dev/stderr"
      printf "  Previous: %s\n", prev > "/dev/stderr"
      printf "  Current:  %s\n", $0 > "/dev/stderr"
      exit 1
    }
    
    {prev = $0}
    
    END {
      if (NR > 0 && !found_error) {
        printf "Catalog is SORTED correctly ✓ (checked %d records)\n", NR > "/dev/stderr"
      }
    }
  '
