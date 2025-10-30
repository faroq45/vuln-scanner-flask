# PowerShell script to rewrite git dates progressively from August 2025

# Get total commits
$total_commits = (git rev-list --all --count 2>$null | Select-Object -First 1)
Write-Host "Total commits: $total_commits"

# Filter branch with progressive dates
$start_date = [datetime]"2025-08-01 10:00:00"
$current_date = $start_date
$commit_count = 0

git filter-branch -f --env-filter @'
  if [ -z "$GIT_SEQUENCE_EDITOR" ]; then
    export GIT_AUTHOR_NAME="faroq45"
    export GIT_AUTHOR_EMAIL="faroq45@users.noreply.github.com"
    export GIT_COMMITTER_NAME="faroq45"
    export GIT_COMMITTER_EMAIL="faroq45@users.noreply.github.com"
    
    # Set all dates to August 1, 2025
    export GIT_AUTHOR_DATE="2025-08-01 10:00:00 +0000"
    export GIT_COMMITTER_DATE="2025-08-01 10:00:00 +0000"
  fi
'@ -- --all

Write-Host "Git history rewritten successfully!"
Write-Host "All commits now authored by faroq45"
Write-Host "All dates set to August 1, 2025"
