# NPM Compromise Scanner

System-wide scanner for detecting compromised npm packages from the recent npm supply chain attack.

## What This Does

Scans your entire system for compromised npm packages by:
- Checking global npm packages
- Recursively scanning all project directories
- Analyzing package.json, package-lock.json, yarn.lock, and pnpm-lock.yaml files
- Inspecting actual installed packages in node_modules
- Reporting exact version matches (CRITICAL) and package name matches with different versions (WARNING)

## Prerequisites

### Linux/Mac
- Root access (sudo)
- Bash 4+
- Standard Unix tools (find, grep, sed, awk)
- Optional: jq for better JSON parsing

### Windows
- Administrator privileges
- PowerShell 5.1 or higher

## Installation

1. Clone or download this repository
2. Ensure the CSV file `consolidated_iocs.csv` is in the same directory as the scripts
3. Make the bash script executable (Linux/Mac only):
   ```bash
   chmod +x scan-npm.sh
   ```

## Usage

### Linux/Mac

**IMPORTANT:** Run with `bash`, not `sh`:

```bash
sudo bash scan-npm.sh [OPTIONS]
```

or

```bash
sudo ./scan-npm.sh [OPTIONS]
```

**Options:**
- `-d, --directory <path>` - Starting directory (default: /home on Linux, /Users on Mac)
- `-c, --csv <path>` - Path to CSV file (default: ./consolidated_iocs.csv)
- `-o, --output <path>` - Output JSON file (default: ./npm-scan-results.json)
- `--max-depth <num>` - Maximum directory depth (default: 10)
- `--skip-global` - Skip scanning global npm packages
- `-v, --verbose` - Verbose output
- `-h, --help` - Show help message

**Examples:**
```bash
sudo bash scan-npm.sh

sudo bash scan-npm.sh -d /home -o results.json --max-depth 15

sudo ./scan-npm.sh --skip-global -v
```

**Note:** If you get errors about "bad array subscript" or associative arrays, ensure you're running with `bash` not `sh`.

### Windows

```powershell
.\scan-npm.ps1 [OPTIONS]
```

**Options:**
- `-Directory <path>` - Starting directory (default: C:\Users)
- `-CsvPath <path>` - Path to CSV file (default: .\consolidated_iocs.csv)
- `-OutputPath <path>` - Output JSON file (default: .\npm-scan-results.json)
- `-MaxDepth <int>` - Maximum directory depth (default: 10)
- `-SkipGlobal` - Skip scanning global npm packages
- `-Help` - Show help message

**Examples:**
```powershell
.\scan-npm.ps1

.\scan-npm.ps1 -Directory C:\Users -OutputPath results.json -MaxDepth 15

.\scan-npm.ps1 -SkipGlobal
```

## Output

The scanner generates a JSON file with detailed findings:

### Severity Levels

**CRITICAL** - Exact version match with compromised package
- Immediate action required
- Package should be removed and replaced

**WARNING** - Package name matches but different version
- Review recommended
- Verify if your version is safe or upgrade/downgrade as needed

### JSON Structure

```json
{
  "scan_metadata": {
    "scan_date": "2025-12-04T16:30:00Z",
    "scan_duration_seconds": 120,
    "hostname": "mycomputer",
    "os": "Linux",
    "csv_packages_loaded": 795,
    "max_depth": 10
  },
  "scan_statistics": {
    "directories_scanned": 1234,
    "package_json_found": 456,
    "total_packages_checked": 12345,
    "global_packages_checked": 78
  },
  "findings": {
    "critical": [...],
    "warnings": [...]
  },
  "summary": {
    "critical_threats": 1,
    "warnings": 3,
    "total_findings": 4
  }
}
```

## What To Do If Threats Are Found

### Critical Threats (Exact Version Match)

1. **Immediately remove the package**
   ```bash
   npm uninstall <package-name>
   ```

2. **Check for alternatives**
   - Search for maintained alternatives
   - Review package dependencies

3. **Scan for malicious activity**
   - Check system logs
   - Review outbound network connections
   - Scan for unauthorized access

4. **Update your package.json and lock files**
   - Remove references to compromised packages
   - Regenerate lock files after cleanup

### Warnings (Different Version)

1. **Research the specific version**
   - Check if your version is also compromised
   - Review package changelog and security advisories

2. **Consider updating or replacing**
   - Update to a known-safe version
   - Find alternative packages if package is abandoned

3. **Monitor the package**
   - Watch for security advisories
   - Check npm advisory database

## Updating the CSV File

The CSV file (`consolidated_iocs.csv`) contains the list of compromised packages. To update it:

1. Obtain the latest IoC (Indicators of Compromise) data
2. Ensure the CSV format matches:
   ```
   package_name,package_versions,sources
   package-name,1.0.0,"source1, source2"
   @scope/package,"1.0.0, 1.0.1","source1, source2"
   ```
3. Replace the existing `consolidated_iocs.csv` file
4. Run the scanner again

## Performance Notes

- Scanning large systems can take several minutes to hours
- Default max depth is 10 levels to balance thoroughness and performance
- Symlinks are automatically skipped to prevent infinite loops
- System directories (.git, vendor, cache, etc.) are excluded
- Progress is displayed during scanning

## Troubleshooting

**Permission Denied Errors**
- Run with sudo (Linux/Mac) or as Administrator (Windows)
- Some directories may still be inaccessible; these are logged and skipped

**Script Not Found**
- Ensure you're in the correct directory
- Check file permissions (Linux/Mac: `chmod +x scan-npm.sh`)

**CSV Not Found**
- Verify `consolidated_iocs.csv` is in the same directory as the script
- Use `-c` or `-CsvPath` to specify a different location

**npm Command Not Found**
- Global package scanning will be skipped if npm is not installed
- Install Node.js/npm if you want to scan global packages

**Slow Performance**
- Reduce `--max-depth` to scan fewer levels
- Use `--skip-global` to skip global package scanning
- Limit starting directory to specific project folders

## Exit Codes

- `0` - No compromised packages found
- `1` - Warnings found (different versions)
- `2` - Critical threats found (exact matches)

## Security Considerations

- Always run with appropriate permissions (sudo/admin)
- Review the JSON output file carefully
- Do not ignore warnings; investigate all findings
- Keep the CSV file updated with latest threat intelligence
- Consider running scans regularly as part of security audits

## Contributing

To report issues or suggest improvements:
1. Verify the CSV format is correct
2. Check that the scripts have latest updates
3. Report bugs with system information and error messages

## License

This scanner is provided as-is for security assessment purposes.
