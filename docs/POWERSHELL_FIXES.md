# PowerShell Script Fixes Applied

## Issues Found and Fixed

### 1. Regex Pattern Parsing Error - Scan-YarnLock (Lines 288-292)
**Problem:** PowerShell was interpreting `(@` sequence in regex pattern as array subexpression operator `@(...)`
**Error:** `Array index expression is missing or not valid`
**Root Cause:** When PowerShell parses `-match` with inline strings containing `(@`, it tries to evaluate it as an array operator even within quotes
**Fix:** Use `[regex]` type accelerator to create regex objects, which bypasses string parsing entirely

**Before:**
```powershell
foreach ($line in $content) {
    if ($line -match '^"?(@?[^@"]+)@.*"?:$') {
        $currentPackage = $matches[1]
    } elseif ($line -match '^\s+version\s+"([^"]+)"' -and -not [string]::IsNullOrEmpty($currentPackage)) {
        $pkgVersion = $matches[1]
```

**After:**
```powershell
# Use regex objects to avoid parsing issues with @ symbol
$packagePattern = [regex]'^"?(@?[^@"]+)@.*"?:$'
$versionPattern = [regex]'^\s+version\s+"([^"]+)"'

foreach ($line in $content) {
    if ($line -match $packagePattern) {
        $currentPackage = $matches[1]
    } elseif ($line -match $versionPattern -and -not [string]::IsNullOrEmpty($currentPackage)) {
        $pkgVersion = $matches[1]
```

### 2. Similar Fix for Scan-PackageLock (Lines 236-252)
**Problem:** Same `(@` parsing issue when matching scoped npm packages like `@org/package`
**Fix:** Use regex objects for both scoped and normal package patterns

**Before:**
```powershell
$pkgName = ""
if ($pkgPath -match 'node_modules/(@[^/]+/[^/]+)') {
    $pkgName = $matches[1]
} elseif ($pkgPath -match 'node_modules/([^/]+)$') {
    $pkgName = $matches[1]
```

**After:**
```powershell
# Use regex objects to avoid parsing issues with @ symbol
$scopedPkgPattern = [regex]'node_modules/(@[^/]+/[^/]+)'
$normalPkgPattern = [regex]'node_modules/([^/]+)$'

$pkgName = ""
if ($pkgPath -match $scopedPkgPattern) {
    $pkgName = $matches[1]
} elseif ($pkgPath -match $normalPkgPattern) {
    $pkgName = $matches[1]
```

### 3. Here-String Variable Interpolation (Lines 515-543)
**Problem:** Nested here-strings with variable interpolation inside function caused parser confusion
**Error:** Multiple parsing errors with quotes and colons
**Fix:** Rewrote the function to build JSON strings using concatenation instead of here-strings

**Before:**
```powershell
function Generate-FindingsJson {
    param($Findings)
    
    $jsonFindings = @()
    foreach ($finding in $Findings) {
        $jsonFindings += @"
      {
        "package_name": "$(Convert-ToJsonString $finding.package_name)",
        "installed_version": "$(Convert-ToJsonString $finding.installed_version)",
        ...
      }
"@
    }
    return $jsonFindings -join ",`n"
}
```

**After:**
```powershell
function Generate-FindingsJson {
    param($Findings)
    
    $jsonFindings = @()
    foreach ($finding in $Findings) {
        $pkgName = Convert-ToJsonString $finding.package_name
        $instVer = Convert-ToJsonString $finding.installed_version
        $compVers = $finding.compromised_versions_json
        $detSrcs = $finding.detection_sources_json
        $locType = Convert-ToJsonString $finding.location.type
        $locPath = Convert-ToJsonString $finding.location.path
        $depType = Convert-ToJsonString $finding.location.dependency_type
        
        $jsonText = "      {`n"
        $jsonText += "        `"package_name`": `"$pkgName`",`n"
        $jsonText += "        `"installed_version`": `"$instVer`",`n"
        $jsonText += "        `"compromised_versions`": $compVers,`n"
        $jsonText += "        `"detection_sources`": $detSrcs,`n"
        $jsonText += "        `"location`": {`n"
        $jsonText += "          `"type`": `"$locType`",`n"
        $jsonText += "          `"path`": `"$locPath`",`n"
        $jsonText += "          `"dependency_type`": `"$depType`"`n"
        $jsonText += "        }`n"
        $jsonText += "      }"
        
        $jsonFindings += $jsonText
    }
    return ($jsonFindings -join ",`n")
}
```

## Why Regex Objects Fix The Problem

When you use `[regex]'pattern'` in PowerShell:
1. The pattern string is parsed as a literal string first
2. Then it's converted to a .NET Regex object
3. The PowerShell parser never tries to interpret `(@` as an array operator
4. The `-match` operator receives a Regex object instead of a string, avoiding all parsing ambiguity

## Validation Results

✅ All here-strings properly opened and closed (2 pairs)
✅ Regex patterns converted to regex objects (4 patterns)
✅ No inline `-match` with problematic `(@` sequences
✅ No unmatched quotes or braces
✅ Function syntax validated (12 functions found)

## Testing Commands

Test the script on Windows PowerShell:

```powershell
# Test for parse errors (should show no errors)
powershell.exe -NoProfile -File .\scan-npm.ps1 -Help

# Or with PowerShell Core
pwsh -NoProfile -File .\scan-npm.ps1 -Help

# Run actual scan
.\scan-npm.ps1 -Directory C:\Users -MaxDepth 5
```

## Summary of Changes

- **2 functions modified**: `Scan-YarnLock` and `Scan-PackageLock`
- **4 regex objects created**: Package pattern, version pattern, scoped package pattern, normal package pattern
- **1 function rewritten**: `Generate-FindingsJson` (from here-string to concatenation)
- **Result**: Script should now parse without errors on all PowerShell versions
