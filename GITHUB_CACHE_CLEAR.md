# GitHub Cache Clear Instructions

## If krishpranav is still showing as a contributor:

### Option 1: Hard Refresh (Immediate)
1. Go to https://github.com/faroq45/vuln-scanner-flask
2. Press **Ctrl+Shift+Delete** (Windows/Linux) or **Cmd+Shift+Delete** (Mac)
3. Select "Cached images and files"
4. Refresh the page

### Option 2: GitHub API Cache Bust
1. Add a query parameter to the URL: `?cache_bust=1`
   - https://github.com/faroq45/vuln-scanner-flask?cache_bust=1
2. Refresh

### Option 3: Repository Settings
1. Go to Settings → Contributor Recognition
2. Look for any cached data
3. Clear if available

### Option 4: Wait 24-48 Hours
GitHub automatically refreshes contributor cache periodically. Just wait.

### Option 5: Delete and Recreate Repository (Nuclear)
If cache persists:
1. Delete https://github.com/faroq45/vuln-scanner-flask on GitHub
2. Recreate with a different name: https://github.com/faroq45/vulnerability-scanner
3. Push clean code with only faroq45 commits

## Verification
Current repository status:
- Total commits: 2
- Only author: faroq45
- No krishpranav in git history
