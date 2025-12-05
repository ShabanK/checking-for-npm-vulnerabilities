#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Directory = "C:\Users",
    
    [Parameter(Mandatory=$false)]
    [string]$CsvPath = "",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "",
    
    [Parameter(Mandatory=$false)]
    [int]$MaxDepth = 10,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipGlobal,
    
    [Parameter(Mandatory=$false)]
    [switch]$Help
)

$VERSION = "1.0.0"
$StartTime = Get-Date

if ($Help) {
    Write-Host @"
NPM Compromise Scanner v$VERSION
Scans system for compromised npm packages

Usage: .\scan-npm.ps1 [OPTIONS]

Options:
  -Directory <path>         Starting directory (default: C:\Users)
  -CsvPath <path>           Path to CSV file (default: .\consolidated_iocs.csv)
  -OutputPath <path>        Output JSON file (default: .\npm-scan-results.json)
  -MaxDepth <int>           Maximum directory depth (default: 10)
  -SkipGlobal              Skip scanning global npm packages
  -Help                     Show this help message

Example:
  .\scan-npm.ps1 -Directory C:\Users -OutputPath results.json -MaxDepth 15

"@
    exit 0
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if ([string]::IsNullOrEmpty($CsvPath)) {
    $CsvPath = Join-Path $ScriptDir "consolidated_iocs.csv"
}

if ([string]::IsNullOrEmpty($OutputPath)) {
    $OutputPath = Join-Path $ScriptDir "npm-scan-results.json"
}

if (-not (Test-Path $CsvPath)) {
    Write-Error "CSV file not found: $CsvPath"
    exit 1
}

if (-not (Test-Path $Directory)) {
    Write-Error "Search directory not found: $Directory"
    exit 1
}

$CompromisedPackages = @{}
$CompromisedVersions = @{}
$CompromisedSources = @{}

$DirsScanned = 0
$PackageJsonCount = 0
$PackageLockCount = 0
$YarnLockCount = 0
$PnpmLockCount = 0
$NodeModulesCount = 0
$GlobalPackagesCount = 0
$PackagesChecked = 0
$PermissionErrors = 0

$CriticalFindings = @()
$WarningFindings = @()
$Errors = @()

Write-Host "Loading compromised packages from $CsvPath..."

$CsvContent = Get-Content $CsvPath | Select-Object -Skip 1
$TotalCompromised = 0

foreach ($line in $CsvContent) {
    if ([string]::IsNullOrWhiteSpace($line)) {
        continue
    }
    
    $parts = $line -split ',(?=(?:[^"]*"[^"]*")*[^"]*$)'
    
    if ($parts.Count -lt 3) {
        continue
    }
    
    $packageName = $parts[0].Trim()
    $packageVersions = $parts[1].Trim() -replace '"', ''
    $sources = $parts[2].Trim() -replace '"', ''
    
    $CompromisedPackages[$packageName] = $true
    $CompromisedVersions[$packageName] = $packageVersions
    $CompromisedSources[$packageName] = $sources
    
    $TotalCompromised++
}

Write-Host "✓ Loaded $TotalCompromised compromised packages"

function Convert-ToJsonString {
    param([string]$text)
    return $text -replace '\\', '\\' -replace '"', '\"' -replace "`n", '\n' -replace "`r", '\r' -replace "`t", '\t'
}

function Convert-VersionsToJsonArray {
    param([string]$versions)
    
    $versionArray = $versions -split ',' | ForEach-Object { $_.Trim() }
    $jsonArray = $versionArray | ForEach-Object { "`"$(Convert-ToJsonString $_)`"" }
    return "[" + ($jsonArray -join ",") + "]"
}

function Convert-SourcesToJsonArray {
    param([string]$sources)
    
    $sourceArray = $sources -split ',' | ForEach-Object { $_.Trim() }
    $jsonArray = $sourceArray | ForEach-Object { "`"$(Convert-ToJsonString $_)`"" }
    return "[" + ($jsonArray -join ",") + "]"
}

function Test-CompromisedPackage {
    param(
        [string]$PackageName,
        [string]$PackageVersion,
        [string]$FilePath,
        [string]$FileType,
        [string]$DependencyType = ""
    )
    
    if ([string]::IsNullOrEmpty($PackageName) -or [string]::IsNullOrEmpty($PackageVersion)) {
        return
    }
    
    if (-not $CompromisedPackages.ContainsKey($PackageName)) {
        return
    }
    
    $script:PackagesChecked++
    
    $compromisedVersions = $CompromisedVersions[$PackageName]
    $sources = $CompromisedSources[$PackageName]
    $isExactMatch = $false
    
    $versionArray = $compromisedVersions -split ',' | ForEach-Object { $_.Trim() }
    foreach ($compVersion in $versionArray) {
        if ($PackageVersion -eq $compVersion) {
            $isExactMatch = $true
            break
        }
    }
    
    $versionsJson = Convert-VersionsToJsonArray $compromisedVersions
    $sourcesJson = Convert-SourcesToJsonArray $sources
    
    $finding = @{
        package_name = $PackageName
        installed_version = $PackageVersion
        compromised_versions_raw = $compromisedVersions
        compromised_versions_json = $versionsJson
        detection_sources_json = $sourcesJson
        location = @{
            type = $FileType
            path = $FilePath
            dependency_type = $DependencyType
        }
        is_exact_match = $isExactMatch
    }
    
    if ($isExactMatch) {
        Write-Host "  🚨 CRITICAL: ${PackageName}@${PackageVersion} (exact match!)" -ForegroundColor Red
        $script:CriticalFindings += $finding
    } else {
        Write-Host "  ⚠️  WARNING: ${PackageName}@${PackageVersion} (compromised versions: ${compromisedVersions})" -ForegroundColor Yellow
        $script:WarningFindings += $finding
    }
}

function Scan-PackageJson {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) {
        return
    }
    
    $script:PackageJsonCount++
    
    try {
        $content = Get-Content $FilePath -Raw -ErrorAction Stop
        $json = $content | ConvertFrom-Json -ErrorAction Stop
        
        if ($json.dependencies) {
            foreach ($dep in $json.dependencies.PSObject.Properties) {
                $pkgName = $dep.Name
                $pkgVersion = $dep.Value -replace '[\^~>=<]', '' -replace '\s.*$', ''
                Test-CompromisedPackage -PackageName $pkgName -PackageVersion $pkgVersion -FilePath $FilePath -FileType "package.json" -DependencyType "dependencies"
            }
        }
        
        if ($json.devDependencies) {
            foreach ($dep in $json.devDependencies.PSObject.Properties) {
                $pkgName = $dep.Name
                $pkgVersion = $dep.Value -replace '[\^~>=<]', '' -replace '\s.*$', ''
                Test-CompromisedPackage -PackageName $pkgName -PackageVersion $pkgVersion -FilePath $FilePath -FileType "package.json" -DependencyType "devDependencies"
            }
        }
    } catch {
    }
}

function Scan-PackageLock {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) {
        return
    }
    
    $script:PackageLockCount++
    
    try {
        $content = Get-Content $FilePath -Raw -ErrorAction Stop
        $json = $content | ConvertFrom-Json -ErrorAction Stop
        
        # Use regex objects to avoid parsing issues with @ symbol
        $at = '@'
        $scopedPkgPattern = [regex]::new('node_modules/(AT[^/]+/[^/]+)' -replace 'AT', $at)
        $normalPkgPattern = [regex]::new('node_modules/([^/]+)$')
        
        if ($json.packages) {
            foreach ($pkg in $json.packages.PSObject.Properties) {
                $pkgPath = $pkg.Name
                $pkgVersion = $pkg.Value.version
                
                if ([string]::IsNullOrEmpty($pkgVersion)) {
                    continue
                }
                
                $pkgName = ""
                if ($pkgPath -match $scopedPkgPattern) {
                    $pkgName = $matches[1]
                } elseif ($pkgPath -match $normalPkgPattern) {
                    $pkgName = $matches[1]
                } else {
                    continue
                }
                
                Test-CompromisedPackage -PackageName $pkgName -PackageVersion $pkgVersion -FilePath $FilePath -FileType "package-lock.json"
            }
        } elseif ($json.dependencies) {
            foreach ($dep in $json.dependencies.PSObject.Properties) {
                $pkgName = $dep.Name
                $pkgVersion = $dep.Value.version
                
                if (-not [string]::IsNullOrEmpty($pkgVersion)) {
                    Test-CompromisedPackage -PackageName $pkgName -PackageVersion $pkgVersion -FilePath $FilePath -FileType "package-lock.json"
                }
            }
        }
    } catch {
    }
}

function Scan-YarnLock {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) {
        return
    }
    
    $script:YarnLockCount++
    
    try {
        $content = Get-Content $FilePath -ErrorAction Stop
        $currentPackage = ""
        
        # Use regex objects to avoid parsing issues with @ symbol
        $at = '@'
        $packagePattern = [regex]::new(('^"?(AT?[^AT"]+)AT.*"?:$' -replace 'AT', $at))
        $versionPattern = [regex]::new('^\s+version\s+"([^"]+)"')
        
        foreach ($line in $content) {
            if ($line -match $packagePattern) {
                $currentPackage = $matches[1]
            } elseif ($line -match $versionPattern -and -not [string]::IsNullOrEmpty($currentPackage)) {
                $pkgVersion = $matches[1]
                Test-CompromisedPackage -PackageName $currentPackage -PackageVersion $pkgVersion -FilePath $FilePath -FileType "yarn.lock"
                $currentPackage = ""
            }
        }
    } catch {
    }
}

function Scan-PnpmLock {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) {
        return
    }
    
    $script:PnpmLockCount++
}

function Scan-NodeModules {
    param([string]$NodeModulesDir)
    
    if (-not (Test-Path $NodeModulesDir)) {
        return
    }
    
    $script:NodeModulesCount++
    
    try {
        $packages = Get-ChildItem -Path $NodeModulesDir -Directory -ErrorAction SilentlyContinue | Where-Object { $_.LinkType -eq $null }
        
        foreach ($pkgDir in $packages) {
            $pkgName = $pkgDir.Name
            
            if ($pkgName.StartsWith("@")) {
                $scopedPackages = Get-ChildItem -Path $pkgDir.FullName -Directory -ErrorAction SilentlyContinue | Where-Object { $_.LinkType -eq $null }
                
                foreach ($scopedPkg in $scopedPackages) {
                    $scopedName = "$pkgName/$($scopedPkg.Name)"
                    $pkgJson = Join-Path $scopedPkg.FullName "package.json"
                    
                    if (Test-Path $pkgJson) {
                        try {
                            $json = Get-Content $pkgJson -Raw | ConvertFrom-Json
                            if ($json.version) {
                                Test-CompromisedPackage -PackageName $scopedName -PackageVersion $json.version -FilePath $pkgJson -FileType "installed"
                            }
                        } catch {
                        }
                    }
                }
            } else {
                $pkgJson = Join-Path $pkgDir.FullName "package.json"
                
                if (Test-Path $pkgJson) {
                    try {
                        $json = Get-Content $pkgJson -Raw | ConvertFrom-Json
                        if ($json.version) {
                            Test-CompromisedPackage -PackageName $pkgName -PackageVersion $json.version -FilePath $pkgJson -FileType "installed"
                        }
                    } catch {
                    }
                }
            }
        }
    } catch {
    }
}

function Scan-GlobalPackages {
    if ($SkipGlobal) {
        return
    }
    
    Write-Host ""
    Write-Host "Scanning global npm packages..."
    
    $npmPrefix = ""
    try {
        $npmPrefix = npm config get prefix 2>$null
    } catch {
        Write-Host "  npm not found, skipping global packages"
        return
    }
    
    if ([string]::IsNullOrEmpty($npmPrefix)) {
        Write-Host "  npm not found, skipping global packages"
        return
    }
    
    $globalNodeModules = Join-Path $npmPrefix "node_modules"
    
    if (-not (Test-Path $globalNodeModules)) {
        Write-Host "  Global node_modules not found at: $globalNodeModules"
        return
    }
    
    Write-Host "  Scanning: $globalNodeModules"
    
    try {
        $packages = Get-ChildItem -Path $globalNodeModules -Directory -ErrorAction SilentlyContinue | Where-Object { $_.LinkType -eq $null }
        
        foreach ($pkgDir in $packages) {
            $pkgName = $pkgDir.Name
            
            if ($pkgName.StartsWith("@")) {
                $scopedPackages = Get-ChildItem -Path $pkgDir.FullName -Directory -ErrorAction SilentlyContinue | Where-Object { $_.LinkType -eq $null }
                
                foreach ($scopedPkg in $scopedPackages) {
                    $scopedName = "$pkgName/$($scopedPkg.Name)"
                    $pkgJson = Join-Path $scopedPkg.FullName "package.json"
                    
                    if (Test-Path $pkgJson) {
                        try {
                            $json = Get-Content $pkgJson -Raw | ConvertFrom-Json
                            if ($json.version) {
                                $script:GlobalPackagesCount++
                                Test-CompromisedPackage -PackageName $scopedName -PackageVersion $json.version -FilePath $pkgJson -FileType "global"
                            }
                        } catch {
                        }
                    }
                }
            } else {
                $pkgJson = Join-Path $pkgDir.FullName "package.json"
                
                if (Test-Path $pkgJson) {
                    try {
                        $json = Get-Content $pkgJson -Raw | ConvertFrom-Json
                        if ($json.version) {
                            $script:GlobalPackagesCount++
                            Test-CompromisedPackage -PackageName $pkgName -PackageVersion $json.version -FilePath $pkgJson -FileType "global"
                        }
                    } catch {
                    }
                }
            }
        }
    } catch {
    }
}

Write-Host ""
Write-Host "Starting system-wide scan from $Directory with max depth $MaxDepth..."
Write-Host ""

Scan-GlobalPackages

Write-Host ""
Write-Host "Scanning local projects..."

$excludeDirs = @('.git', '.svn', '.hg', 'vendor', '.cargo', '.rustup', 'Trash', 'Cache', 'Caches', 'AppData\Local\Temp')

function Get-DirectoriesRecursive {
    param(
        [string]$Path,
        [int]$CurrentDepth = 0,
        [int]$MaxDepth
    )
    
    if ($CurrentDepth -ge $MaxDepth) {
        return
    }
    
    try {
        $dirs = Get-ChildItem -Path $Path -Directory -ErrorAction SilentlyContinue | Where-Object { 
            $_.LinkType -eq $null -and 
            $_.Name -notin $excludeDirs -and
            -not $_.Name.StartsWith('.')
        }
        
        foreach ($dir in $dirs) {
            $script:DirsScanned++
            
            if ($script:DirsScanned % 100 -eq 0) {
                Write-Progress -Activity "Scanning directories" -Status "Scanned: $script:DirsScanned directories" -PercentComplete -1
            }
            
            $dir.FullName
            
            Get-DirectoriesRecursive -Path $dir.FullName -CurrentDepth ($CurrentDepth + 1) -MaxDepth $MaxDepth
        }
    } catch {
    }
}

$allDirs = @($Directory) + @(Get-DirectoriesRecursive -Path $Directory -CurrentDepth 0 -MaxDepth $MaxDepth)

foreach ($dir in $allDirs) {
    $packageJsonPath = Join-Path $dir "package.json"
    $packageLockPath = Join-Path $dir "package-lock.json"
    $yarnLockPath = Join-Path $dir "yarn.lock"
    $pnpmLockPath = Join-Path $dir "pnpm-lock.yaml"
    $nodeModulesPath = Join-Path $dir "node_modules"
    
    if (Test-Path $packageJsonPath) {
        Scan-PackageJson -FilePath $packageJsonPath
    }
    
    if (Test-Path $packageLockPath) {
        Scan-PackageLock -FilePath $packageLockPath
    }
    
    if (Test-Path $yarnLockPath) {
        Scan-YarnLock -FilePath $yarnLockPath
    }
    
    if (Test-Path $pnpmLockPath) {
        Scan-PnpmLock -FilePath $pnpmLockPath
    }
    
    if (Test-Path $nodeModulesPath) {
        Scan-NodeModules -FilePath $nodeModulesPath
    }
}

Write-Progress -Activity "Scanning directories" -Completed

$EndTime = Get-Date
$Duration = [int]($EndTime - $StartTime).TotalSeconds

Write-Host ""
Write-Host "Generating JSON report..."

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

$scanDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$hostname = $env:COMPUTERNAME

$criticalJson = Generate-FindingsJson -Findings $CriticalFindings
$warningsJson = Generate-FindingsJson -Findings $WarningFindings

$jsonOutput = @"
{
  "scan_metadata": {
    "scan_date": "$scanDate",
    "scan_duration_seconds": $Duration,
    "hostname": "$(Convert-ToJsonString $hostname)",
    "os": "Windows",
    "script_version": "$VERSION",
    "csv_source": "$(Convert-ToJsonString $CsvPath)",
    "csv_packages_loaded": $TotalCompromised,
    "max_depth": $MaxDepth
  },
  "scan_statistics": {
    "directories_scanned": $DirsScanned,
    "package_json_found": $PackageJsonCount,
    "package_lock_json_found": $PackageLockCount,
    "yarn_lock_found": $YarnLockCount,
    "pnpm_lock_found": $PnpmLockCount,
    "node_modules_directories": $NodeModulesCount,
    "total_packages_checked": $PackagesChecked,
    "global_packages_checked": $GlobalPackagesCount,
    "permission_errors": $PermissionErrors
  },
  "findings": {
    "critical": [
$criticalJson
    ],
    "warnings": [
$warningsJson
    ]
  },
  "summary": {
    "critical_threats": $($CriticalFindings.Count),
    "warnings": $($WarningFindings.Count),
    "total_findings": $($CriticalFindings.Count + $WarningFindings.Count),
    "unique_compromised_packages": $($CriticalFindings.Count + $WarningFindings.Count)
  }
}
"@

$jsonOutput | Out-File -FilePath $OutputPath -Encoding UTF8

Write-Host "✓ Results written to: $OutputPath"
Write-Host ""
Write-Host "=========================================="
Write-Host "           SCAN COMPLETE"
Write-Host "=========================================="
Write-Host "Duration: ${Duration}s"
Write-Host "Summary:"
Write-Host "  - Critical threats: $($CriticalFindings.Count)"
Write-Host "  - Warnings: $($WarningFindings.Count)"
Write-Host "  - Directories scanned: $DirsScanned"
Write-Host "  - Packages checked: $PackagesChecked"
Write-Host "  - Global packages checked: $GlobalPackagesCount"
Write-Host "=========================================="

if ($CriticalFindings.Count -gt 0) {
    Write-Host ""
    Write-Host "⚠️  CRITICAL THREATS DETECTED!" -ForegroundColor Red
    Write-Host "Review $OutputPath for details"
    exit 2
}

if ($WarningFindings.Count -gt 0) {
    Write-Host ""
    Write-Host "⚠️  WARNINGS DETECTED" -ForegroundColor Yellow
    Write-Host "Review $OutputPath for details"
    exit 1
}

Write-Host ""
Write-Host "✓ No compromised packages found" -ForegroundColor Green
exit 0
