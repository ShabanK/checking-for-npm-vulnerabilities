# NPM Compromise Scanner - Changes Log

## Version 1.0.0 - 2025-12-04

### Issues Fixed

#### 1. Bash Script - Array Subscript Error
**Problem:** `COMPROMISED_PACKAGES: bad array subscript` error when checking if package exists in associative array.

**Root Cause:** Using `[[ -z "${COMPROMISED_PACKAGES[$pkg_name]:-}" ]]` which doesn't properly work with bash's `set -u` flag in all contexts.

**Solution:** Changed to `[[ -v COMPROMISED_PACKAGES[$pkg_name] ]]` which is the proper bash 4.3+ syntax for checking if an array key exists.

**File:** `scan-npm.sh` line 215

---

#### 2. Bash Script - JSON Parsing Failure
**Problem:** Script was not detecting packages in package.json files.

**Root Cause:** Regex `grep -o '"dependencies"[[:space:]]*:[[:space:]]*{[^}]*}'` attempted to match entire multiline JSON block on a single line, which fails for multiline JSON.

**Solution:** Rewrote `scan_package_json()` function to:
- Parse JSON line-by-line
- Track state (in dependencies block, in devDependencies block)
- Match package entries as encountered
- Properly handle multiline formatted JSON

**File:** `scan-npm.sh` lines 266-307

---

#### 3. Bash Script - Shell Detection
**Problem:** When run with `sh` instead of `bash`, script would fail with cryptic errors.

**Root Cause:** No detection of shell type; bash features used when invoked via sh.

**Solution:** Added shell detection using `ps -o comm=` to check if script is invoked with `sh`, and show clear error message with correct usage instructions.

**File:** `scan-npm.sh` lines 3-16

---

#### 4. PowerShell Script - Defensive Programming
**Problem:** No explicit validation of empty/null package names and versions.

**Root Cause:** While PowerShell's native error handling caught most cases, explicit validation was missing.

**Solution:** Added null/empty checks at the start of `Test-CompromisedPackage`:
```powershell
if ([string]::IsNullOrEmpty($PackageName) -or [string]::IsNullOrEmpty($PackageVersion)) {
    return
}
```

**File:** `scan-npm.ps1` lines 147-150

---

### Enhancements

1. **Better Error Messages**
   - Clear error when script is run with `sh` instead of `bash`
   - Helpful guidance showing correct usage

2. **Improved Robustness**
   - Both scripts now handle edge cases gracefully
   - Consistent null/empty validation across bash and PowerShell

3. **Documentation**
   - Added QUICK_START.txt for easy reference
   - Added TEST_VERIFICATION.txt with test results
   - Added this CHANGES.md file

---

### Testing

All functionality tested and verified:
- ✅ Detects compromised packages (exact version matches)
- ✅ Warns about packages with different versions  
- ✅ Handles scoped packages (@org/package)
- ✅ Strips version prefixes (^, ~, >=, etc.)
- ✅ Parses multiline JSON correctly
- ✅ Generates valid JSON output
- ✅ Shows clear error messages

---

### Files Modified

- `scan-npm.sh` - Bash script for Linux/Mac (3 critical fixes)
- `scan-npm.ps1` - PowerShell script for Windows (1 enhancement)
- `README.md` - Updated with bash requirement clarification
- `QUICK_START.txt` - Updated with correct usage info
- `TEST_VERIFICATION.txt` - Updated with both script status

---

### Breaking Changes

None. The scripts now work correctly where they previously failed.

---

### Compatibility

**Linux/Mac (bash):**
- Requires bash 4.0+ (automatically checked)
- Requires sudo/root access
- Tested on bash 5.3.3

**Windows (PowerShell):**
- Requires PowerShell 5.1+ (enforced by #Requires directive)
- Requires Administrator privileges (enforced by #Requires directive)
- Tested on PowerShell 5.1+

---

### Usage

**Linux/Mac:**
```bash
cd /home/dude/Work/npm-check
sudo bash scan-npm.sh
```

**Windows:**
```powershell
cd C:\path\to\npm-check
.\scan-npm.ps1
```

---

### Known Limitations

1. pnpm-lock.yaml files are detected but not fully parsed yet
2. package-lock.json full parsing requires jq (bash version)
3. Very large node_modules trees may take time to scan
4. Requires elevated privileges for system-wide scanning

---

### Future Improvements

- [ ] Add pnpm-lock.yaml full parsing support
- [ ] Add parallel scanning for better performance
- [ ] Add option to scan without elevated privileges (user-only mode)
- [ ] Add real-time progress bar with ETA
- [ ] Add HTML report output option
- [ ] Add email notification option for CI/CD integration

