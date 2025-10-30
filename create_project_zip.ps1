# VulScanner Project ZIP Creator
# Creates a clean zip file for sharing, excluding unnecessary files

$SourcePath = "C:\vulnerability-scanner\vuln-scanner-flask"
$DestinationPath = "C:\vulnerability-scanner\VulScanner-Project.zip"
$TempPath = "C:\vulnerability-scanner\temp-vulscanner"

Write-Host "🔄 Creating VulScanner project zip for sharing..." -ForegroundColor Cyan

# Remove existing zip if it exists
if (Test-Path $DestinationPath) {
    Remove-Item $DestinationPath -Force
    Write-Host "📁 Removed existing zip file" -ForegroundColor Yellow
}

# Remove existing temp directory if it exists
if (Test-Path $TempPath) {
    Remove-Item $TempPath -Recurse -Force
}

# Create temp directory
New-Item -ItemType Directory -Path $TempPath | Out-Null

# Files and directories to exclude
$ExcludePatterns = @(
    "__pycache__",
    "*.pyc",
    "*.log",
    "vulnscanner.db",
    "*.tmp",
    "logs\*",
    "env\*",
    ".git",
    "node_modules",
    "*.db-journal",
    "scan_results.json"
)

Write-Host "📋 Copying files (excluding cache, logs, and database files)..." -ForegroundColor Green

# Copy all files except excluded ones
Get-ChildItem -Path $SourcePath -Recurse | ForEach-Object {
    $relativePath = $_.FullName.Replace($SourcePath, "")
    $shouldExclude = $false
    
    foreach ($pattern in $ExcludePatterns) {
        if ($_.Name -like $pattern -or $relativePath -like "*\$pattern" -or $relativePath -like "*$pattern*") {
            $shouldExclude = $true
            break
        }
    }
    
    if (-not $shouldExclude) {
        $destPath = Join-Path $TempPath $relativePath
        $destDir = Split-Path $destPath -Parent
        
        if (-not (Test-Path $destDir)) {
            New-Item -ItemType Directory -Path $destDir -Force | Out-Null
        }
        
        if ($_.PSIsContainer -eq $false) {
            Copy-Item $_.FullName $destPath -Force
        }
    }
}

# Create the zip file
Write-Host "🗜️ Compressing files into zip archive..." -ForegroundColor Green
Compress-Archive -Path "$TempPath\*" -DestinationPath $DestinationPath -Force

# Clean up temp directory
Remove-Item $TempPath -Recurse -Force

# Get zip file info
$zipInfo = Get-Item $DestinationPath
$zipSizeMB = [math]::Round($zipInfo.Length / 1MB, 2)

Write-Host "✅ VulScanner project zip created successfully!" -ForegroundColor Green
Write-Host "📁 Location: $DestinationPath" -ForegroundColor White
Write-Host "📊 Size: $zipSizeMB MB" -ForegroundColor White
Write-Host "📅 Created: $($zipInfo.CreationTime)" -ForegroundColor White

# List contents summary
Write-Host "`n📋 Package Contents Summary:" -ForegroundColor Cyan
$itemCount = (Get-ChildItem $SourcePath -Recurse | Where-Object { 
    $relativePath = $_.FullName.Replace($SourcePath, "")
    $shouldExclude = $false
    
    foreach ($pattern in $ExcludePatterns) {
        if ($_.Name -like $pattern -or $relativePath -like "*\$pattern" -or $relativePath -like "*$pattern*") {
            $shouldExclude = $true
            break
        }
    }
    
    -not $shouldExclude -and $_.PSIsContainer -eq $false
}).Count

Write-Host "   • Source code files: $itemCount items" -ForegroundColor White
Write-Host "   • Documentation: Technical docs + PDF" -ForegroundColor White
Write-Host "   • VS Code configuration: Launch, tasks, settings" -ForegroundColor White
Write-Host "   • Static assets: CSS, JS, templates" -ForegroundColor White
Write-Host "   • Excluded: Cache files, logs, database files" -ForegroundColor Gray

Write-Host "`n🎉 Ready to share your VulScanner project!" -ForegroundColor Green