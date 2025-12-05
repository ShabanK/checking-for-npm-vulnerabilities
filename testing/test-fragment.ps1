# Removed admin requirement for testing
# #Requires -RunAsAdministrator


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

