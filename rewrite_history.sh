#!/bin/bash
# This script rewrites git history to change all authors to faroq45

git filter-branch -f --env-filter '
export GIT_COMMIT_DATE="2025-10-30 14:42:52"
export GIT_AUTHOR_NAME="faroq45"
export GIT_AUTHOR_EMAIL="faroq45@users.noreply.github.com"
export GIT_COMMITTER_NAME="faroq45"
export GIT_COMMITTER_EMAIL="faroq45@users.noreply.github.com"
' -- --all
