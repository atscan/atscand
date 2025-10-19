pv plc_cache/*.jsonl.zst | zstdcat | \
  jq -r '[.createdAt, .cid, .did] | @tsv' | \
  awk '
    NR > 1 {
      if ($2 == prev_cid) {
        printf "Duplicate CID: %s\n", $2
        printf "  Prev: time=%s DID=%s\n", prev_time, prev_did
        printf "  Curr: time=%s DID=%s\n\n", $1, $3
      }
    }
    {prev_time = $1; prev_cid = $2; prev_did = $3}
  '
