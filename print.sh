git ls-tree -r --name-only HEAD | while read filename; do
  echo "--- FILE: $filename ---"
  git show HEAD:"$filename"
  echo ""
done > all_repo_content.txt
