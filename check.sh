pv plc_cache/*.jsonl.zst | zstdcat | \
  jq -r '[.createdAt, .cid, .did] | @tsv' | \
  awk '
    NR > 1 {
      # Track consecutive same timestamps
      if ($1 == prev_time) {
        if (same_streak == 0) {
          same_streak = 2  # Current + previous
          streak_time = $1
          streak_data[1] = prev_time "\t" prev_cid "\t" prev_did
          streak_data[2] = $1 "\t" $2 "\t" $3
        } else {
          same_streak++
          streak_data[same_streak] = $1 "\t" $2 "\t" $3
        }
      } else {
        # Streak ended, check if it was 8+
        if (same_streak >= 8) {
          groups_of_8_plus++
          printf "\n=== Found %d items with same createdAt: %s ===\n", same_streak, streak_time > "/dev/stderr"
          for (i = 1; i <= same_streak; i++) {
            split(streak_data[i], parts, "\t")
            printf "  %s | CID: %s | DID: %s\n", parts[1], parts[2], parts[3] > "/dev/stderr"
          }
          
          # Track maximum
          if (same_streak > max_streak) {
            max_streak = same_streak
            max_time = streak_time
          }
        }
        same_streak = 0
        delete streak_data
      }
    }

    {prev_time = $1; prev_cid = $2; prev_did = $3}

    END {
      # Check last streak
      if (same_streak >= 8) {
        groups_of_8_plus++
        printf "\n=== Found %d items with same createdAt: %s ===\n", same_streak, streak_time > "/dev/stderr"
        for (i = 1; i <= same_streak; i++) {
          split(streak_data[i], parts, "\t")
          printf "  %s | CID: %s | DID: %s\n", parts[1], parts[2], parts[3] > "/dev/stderr"
        }
        
        # Track maximum
        if (same_streak > max_streak) {
          max_streak = same_streak
          max_time = streak_time
        }
      }
      
      printf "\n=== SUMMARY ===\n" > "/dev/stderr"
      printf "Total groups of 8+ items with same createdAt: %d\n", groups_of_8_plus > "/dev/stderr"
      if (max_streak > 0) {
        printf "Largest group: %d items at %s\n", max_streak, max_time > "/dev/stderr"
      }
    }
  '

