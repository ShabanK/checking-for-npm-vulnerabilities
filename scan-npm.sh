#!/usr/bin/env bash

case "$(ps -o comm= $$)" in
    sh|dash|*/sh|*/dash)
        echo ""
        echo "================================================================"
        echo "ERROR: You are running this script with 'sh'"
        echo "================================================================"
        echo ""
        echo "This script MUST be run with bash, not sh."
        echo ""
        echo "❌  What you did:     sudo sh scan-npm.sh"
        echo "✓   What you need:    sudo bash scan-npm.sh"
        echo "✓   Or simply:        sudo ./scan-npm.sh"
        echo ""
        echo "================================================================"
        exit 1
        ;;
esac

if [ -z "$BASH_VERSION" ]; then
    echo "ERROR: This script requires bash"
    echo "Please run with: bash $0"
    exit 1
fi

if [ "${BASH_VERSINFO:-0}" -lt 4 ]; then
    echo "ERROR: This script requires bash 4.0 or higher (you have ${BASH_VERSION:-unknown})"
    exit 1
fi

set -euo pipefail

VERSION="1.0.0"
START_TIME=$(date +%s)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CSV_FILE="$SCRIPT_DIR/consolidated_iocs.csv"
OUTPUT_FILE="$SCRIPT_DIR/npm-scan-results.json"
MAX_DEPTH=10
SKIP_GLOBAL=0
VERBOSE=0

if [[ "$OSTYPE" == "darwin"* ]]; then
    DEFAULT_SEARCH_DIR="/Users"
else
    DEFAULT_SEARCH_DIR="/home"
fi
SEARCH_DIR="$DEFAULT_SEARCH_DIR"

declare -A COMPROMISED_PACKAGES
declare -A COMPROMISED_VERSIONS
declare -A COMPROMISED_SOURCES

DIRS_SCANNED=0
PACKAGE_JSON_COUNT=0
PACKAGE_LOCK_COUNT=0
YARN_LOCK_COUNT=0
PNPM_LOCK_COUNT=0
NODE_MODULES_COUNT=0
GLOBAL_PACKAGES_COUNT=0
PACKAGES_CHECKED=0
PERMISSION_ERRORS=0

declare -a CRITICAL_FINDINGS=()
declare -a WARNING_FINDINGS=()
declare -a ERRORS=()

show_help() {
    cat << EOF
NPM Compromise Scanner v${VERSION}
Scans system for compromised npm packages

Usage: sudo $0 [OPTIONS]

Options:
  -d, --directory <path>    Starting directory (default: $DEFAULT_SEARCH_DIR)
  -c, --csv <path>          Path to CSV file (default: ./consolidated_iocs.csv)
  -o, --output <path>       Output JSON file (default: ./npm-scan-results.json)
  --max-depth <num>         Maximum directory depth (default: 10)
  --skip-global             Skip scanning global npm packages
  -v, --verbose             Verbose output
  -h, --help                Show this help message

Example:
  sudo $0 -d /home -o results.json --max-depth 15

EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--directory)
            SEARCH_DIR="$2"
            shift 2
            ;;
        -c|--csv)
            CSV_FILE="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --max-depth)
            MAX_DEPTH="$2"
            shift 2
            ;;
        --skip-global)
            SKIP_GLOBAL=1
            shift
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -h|--help)
            show_help
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root (use sudo)"
   exit 1
fi

if [[ ! -f "$CSV_FILE" ]]; then
    echo "Error: CSV file not found: $CSV_FILE"
    exit 1
fi

if [[ ! -d "$SEARCH_DIR" ]]; then
    echo "Error: Search directory not found: $SEARCH_DIR"
    exit 1
fi

echo "Loading compromised packages from $CSV_FILE..."

CSV_LINE_COUNT=0
while IFS=',' read -r package_name package_versions sources; do
    CSV_LINE_COUNT=$((CSV_LINE_COUNT + 1))
    
    if [[ $CSV_LINE_COUNT -eq 1 ]]; then
        continue
    fi
    
    package_name=$(echo "$package_name" | xargs)
    package_versions=$(echo "$package_versions" | sed 's/"//g' | xargs)
    sources=$(echo "$sources" | sed 's/"//g' | xargs)
    
    COMPROMISED_PACKAGES["$package_name"]=1
    COMPROMISED_VERSIONS["$package_name"]="$package_versions"
    COMPROMISED_SOURCES["$package_name"]="$sources"
    
done < "$CSV_FILE"

TOTAL_COMPROMISED=$((CSV_LINE_COUNT - 1))
echo "✓ Loaded $TOTAL_COMPROMISED compromised packages"

json_escape() {
    echo "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/$/\\n/g' | tr -d '\n' | sed 's/\\n$//'
}

array_to_json() {
    local versions="$1"
    local result="["
    local first=1
    
    IFS=',' read -ra VERSION_ARRAY <<< "$versions"
    for version in "${VERSION_ARRAY[@]}"; do
        version=$(echo "$version" | xargs)
        if [[ $first -eq 1 ]]; then
            first=0
        else
            result+=","
        fi
        result+="\"$(json_escape "$version")\""
    done
    result+="]"
    echo "$result"
}

sources_to_json() {
    local sources="$1"
    local result="["
    local first=1
    
    IFS=',' read -ra SOURCE_ARRAY <<< "$sources"
    for source in "${SOURCE_ARRAY[@]}"; do
        source=$(echo "$source" | xargs)
        if [[ $first -eq 1 ]]; then
            first=0
        else
            result+=","
        fi
        result+="\"$(json_escape "$source")\""
    done
    result+="]"
    echo "$result"
}

check_package() {
    local pkg_name="$1"
    local pkg_version="$2"
    local file_path="$3"
    local file_type="$4"
    local dep_type="${5:-}"
    
    if [[ -z "$pkg_name" ]] || [[ -z "$pkg_version" ]]; then
        return
    fi
    
    # Debug: catch the problematic package
    if ! [[ -v COMPROMISED_PACKAGES[$pkg_name] ]]; then
        return
    fi
    
    PACKAGES_CHECKED=$((PACKAGES_CHECKED + 1))
    
    local compromised_versions="${COMPROMISED_VERSIONS[$pkg_name]}"
    local sources="${COMPROMISED_SOURCES[$pkg_name]}"
    local is_exact_match=0
    
    IFS=',' read -ra VERSION_ARRAY <<< "$compromised_versions"
    for comp_version in "${VERSION_ARRAY[@]}"; do
        comp_version=$(echo "$comp_version" | xargs)
        if [[ "$pkg_version" == "$comp_version" ]]; then
            is_exact_match=1
            break
        fi
    done
    
    local versions_json=$(array_to_json "$compromised_versions")
    local sources_json=$(sources_to_json "$sources")
    
    local finding=$(cat <<EOF
{
  "package_name": "$(json_escape "$pkg_name")",
  "installed_version": "$(json_escape "$pkg_version")",
  "compromised_versions": $versions_json,
  "detection_sources": $sources_json,
  "location": {
    "type": "$(json_escape "$file_type")",
    "path": "$(json_escape "$file_path")",
    "dependency_type": "$(json_escape "$dep_type")"
  }
}
EOF
)
    
    if [[ $is_exact_match -eq 1 ]]; then
        echo "  🚨 CRITICAL: ${pkg_name}@${pkg_version} (exact match!)"
        CRITICAL_FINDINGS+=("$finding")
    else
        echo "  ⚠️  WARNING: ${pkg_name}@${pkg_version} (compromised versions: ${compromised_versions})"
        WARNING_FINDINGS+=("$finding")
    fi
}

scan_package_json() {
    local file_path="$1"
    
    if [[ ! -f "$file_path" ]]; then
        return
    fi
    
    PACKAGE_JSON_COUNT=$((PACKAGE_JSON_COUNT + 1))
    
    if [[ $VERBOSE -eq 1 ]]; then
        echo "Scanning: $file_path"
    fi
    
    local content
    if ! content=$(cat "$file_path" 2>/dev/null); then
        return
    fi
    
    # Parse dependencies section
    local in_deps=0
    local in_devdeps=0
    while IFS= read -r line; do
        if [[ "$line" =~ \"dependencies\"[[:space:]]*:[[:space:]]*\{ ]]; then
            in_deps=1
            continue
        elif [[ "$line" =~ \"devDependencies\"[[:space:]]*:[[:space:]]*\{ ]]; then
            in_devdeps=1
            continue
        elif [[ "$line" =~ ^\s*\} ]]; then
            in_deps=0
            in_devdeps=0
            continue
        fi
        
        if [[ $in_deps -eq 1 ]] || [[ $in_devdeps -eq 1 ]]; then
            if [[ "$line" =~ \"([^\"]+)\"[[:space:]]*:[[:space:]]*\"([^\"]+)\" ]]; then
                local pkg_name="${BASH_REMATCH[1]}"
                local pkg_version="${BASH_REMATCH[2]}"
                pkg_version=$(echo "$pkg_version" | sed 's/[\^~>=<]//g' | cut -d' ' -f1)
                
                if [[ $in_deps -eq 1 ]]; then
                    check_package "$pkg_name" "$pkg_version" "$file_path" "package.json" "dependencies"
                else
                    check_package "$pkg_name" "$pkg_version" "$file_path" "package.json" "devDependencies"
                fi
            fi
        fi
    done <<< "$content"
}

scan_package_lock() {
    local file_path="$1"
    
    if [[ ! -f "$file_path" ]]; then
        return
    fi
    
    PACKAGE_LOCK_COUNT=$((PACKAGE_LOCK_COUNT + 1))
    
    if command -v jq &> /dev/null; then
        local packages=$(jq -r '.packages // .dependencies | to_entries[] | "\(.key)|\(.value.version // "")"' "$file_path" 2>/dev/null || true)
        while IFS='|' read -r pkg_path pkg_version; do
            if [[ -z "$pkg_version" ]]; then
                continue
            fi
            local pkg_name=$(basename "$pkg_path")
            if [[ "$pkg_path" =~ node_modules/(@[^/]+/[^/]+) ]]; then
                pkg_name="${BASH_REMATCH[1]}"
            elif [[ "$pkg_path" =~ node_modules/([^/]+)$ ]]; then
                pkg_name="${BASH_REMATCH[1]}"
            fi
            check_package "$pkg_name" "$pkg_version" "$file_path" "package-lock.json" ""
        done <<< "$packages"
    fi
}

scan_yarn_lock() {
    local file_path="$1"
    
    if [[ ! -f "$file_path" ]]; then
        return
    fi
    
    YARN_LOCK_COUNT=$((YARN_LOCK_COUNT + 1))
    
    local content
    if ! content=$(cat "$file_path" 2>/dev/null); then
        return
    fi
    
    while IFS= read -r line; do
        if [[ "$line" =~ ^\"?(@?[^@\"]+)@.*\"?:$ ]]; then
            local pkg_name="${BASH_REMATCH[1]}"
            read -r next_line
            if [[ "$next_line" =~ version[[:space:]]+\"([^\"]+)\" ]]; then
                local pkg_version="${BASH_REMATCH[1]}"
                check_package "$pkg_name" "$pkg_version" "$file_path" "yarn.lock" ""
            fi
        fi
    done <<< "$content"
}

scan_pnpm_lock() {
    local file_path="$1"
    
    if [[ ! -f "$file_path" ]]; then
        return
    fi
    
    PNPM_LOCK_COUNT=$((PNPM_LOCK_COUNT + 1))
}

scan_node_modules() {
    local node_modules_dir="$1"
    
    if [[ ! -d "$node_modules_dir" ]]; then
        return
    fi
    
    NODE_MODULES_COUNT=$((NODE_MODULES_COUNT + 1))
    
    for pkg_dir in "$node_modules_dir"/*; do
        if [[ ! -d "$pkg_dir" ]]; then
            continue
        fi
        
        local pkg_name=$(basename "$pkg_dir")
        
        if [[ "$pkg_name" == "@"* ]]; then
            for scoped_pkg in "$pkg_dir"/*; do
                if [[ -d "$scoped_pkg" ]]; then
                    local scoped_name="$pkg_name/$(basename "$scoped_pkg")"
                    local pkg_json="$scoped_pkg/package.json"
                    if [[ -f "$pkg_json" ]]; then
                        local version=$(grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "$pkg_json" | sed 's/.*"\([^"]*\)".*/\1/' || echo "")
                        if [[ -n "$version" ]]; then
                            check_package "$scoped_name" "$version" "$pkg_json" "installed" ""
                        fi
                    fi
                fi
            done
        else
            local pkg_json="$pkg_dir/package.json"
            if [[ -f "$pkg_json" ]]; then
                local version=$(grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "$pkg_json" | sed 's/.*"\([^"]*\)".*/\1/' || echo "")
                if [[ -n "$version" ]]; then
                    check_package "$pkg_name" "$version" "$pkg_json" "installed" ""
                fi
            fi
        fi
    done
}

scan_global_packages() {
    if [[ $SKIP_GLOBAL -eq 1 ]]; then
        return
    fi
    
    echo ""
    echo "Scanning global npm packages..."
    
    local npm_prefix=""
    if command -v npm &> /dev/null; then
        npm_prefix=$(npm config get prefix 2>/dev/null || echo "")
    fi
    
    if [[ -z "$npm_prefix" ]]; then
        echo "  npm not found, skipping global packages"
        return
    fi
    
    local global_node_modules="$npm_prefix/lib/node_modules"
    if [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
        global_node_modules="$npm_prefix/node_modules"
    fi
    
    if [[ ! -d "$global_node_modules" ]]; then
        echo "  Global node_modules not found at: $global_node_modules"
        return
    fi
    
    echo "  Scanning: $global_node_modules"
    
    for pkg_dir in "$global_node_modules"/*; do
        if [[ ! -d "$pkg_dir" ]] || [[ -L "$pkg_dir" ]]; then
            continue
        fi
        
        local pkg_name=$(basename "$pkg_dir")
        
        if [[ "$pkg_name" == "@"* ]]; then
            for scoped_pkg in "$pkg_dir"/*; do
                if [[ -d "$scoped_pkg" ]] && [[ ! -L "$scoped_pkg" ]]; then
                    local scoped_name="$pkg_name/$(basename "$scoped_pkg")"
                    local pkg_json="$scoped_pkg/package.json"
                    if [[ -f "$pkg_json" ]]; then
                        local version=$(grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "$pkg_json" | sed 's/.*"\([^"]*\)".*/\1/' || echo "")
                        if [[ -n "$version" ]]; then
                            GLOBAL_PACKAGES_COUNT=$((GLOBAL_PACKAGES_COUNT + 1))
                            check_package "$scoped_name" "$version" "$pkg_json" "global" ""
                        fi
                    fi
                fi
            done
        else
            local pkg_json="$pkg_dir/package.json"
            if [[ -f "$pkg_json" ]]; then
                local version=$(grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "$pkg_json" | sed 's/.*"\([^"]*\)".*/\1/' || echo "")
                if [[ -n "$version" ]]; then
                    GLOBAL_PACKAGES_COUNT=$((GLOBAL_PACKAGES_COUNT + 1))
                    check_package "$pkg_name" "$version" "$pkg_json" "global" ""
                fi
            fi
        fi
    done
}

echo ""
echo "Starting system-wide scan from $SEARCH_DIR with max depth $MAX_DEPTH..."
echo ""

scan_global_packages

echo ""
echo "Scanning local projects..."

while IFS= read -r dir; do
    if [[ -L "$dir" ]]; then
        continue
    fi
    
    DIRS_SCANNED=$((DIRS_SCANNED + 1))
    
    if [[ $((DIRS_SCANNED % 100)) -eq 0 ]]; then
        echo -ne "\rDirectories scanned: $DIRS_SCANNED"
    fi
    
    scan_package_json "$dir/package.json"
    scan_package_lock "$dir/package-lock.json"
    scan_yarn_lock "$dir/yarn.lock"
    scan_pnpm_lock "$dir/pnpm-lock.yaml"
    scan_node_modules "$dir/node_modules"
    
done < <(find "$SEARCH_DIR" -maxdepth "$MAX_DEPTH" -type d \
    ! -path "*/.*" \
    ! -path "*/node_modules/node_modules" \
    ! -path "*/vendor/*" \
    ! -path "*/.cargo/*" \
    ! -path "*/.rustup/*" \
    ! -path "*/Trash/*" \
    ! -path "*/Cache/*" \
    ! -path "*/Caches/*" \
    2>/dev/null || true)

echo -ne "\rDirectories scanned: $DIRS_SCANNED"
echo ""

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo "Generating JSON report..."

generate_json_output() {
    local scan_date=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local hostname=$(hostname)
    local os_name="$OSTYPE"
    
    echo "{"
    echo "  \"scan_metadata\": {"
    echo "    \"scan_date\": \"$scan_date\","
    echo "    \"scan_duration_seconds\": $DURATION,"
    echo "    \"hostname\": \"$(json_escape "$hostname")\","
    echo "    \"os\": \"$(json_escape "$os_name")\","
    echo "    \"script_version\": \"$VERSION\","
    echo "    \"csv_source\": \"$(json_escape "$CSV_FILE")\","
    echo "    \"csv_packages_loaded\": $TOTAL_COMPROMISED,"
    echo "    \"max_depth\": $MAX_DEPTH"
    echo "  },"
    echo "  \"scan_statistics\": {"
    echo "    \"directories_scanned\": $DIRS_SCANNED,"
    echo "    \"package_json_found\": $PACKAGE_JSON_COUNT,"
    echo "    \"package_lock_json_found\": $PACKAGE_LOCK_COUNT,"
    echo "    \"yarn_lock_found\": $YARN_LOCK_COUNT,"
    echo "    \"pnpm_lock_found\": $PNPM_LOCK_COUNT,"
    echo "    \"node_modules_directories\": $NODE_MODULES_COUNT,"
    echo "    \"total_packages_checked\": $PACKAGES_CHECKED,"
    echo "    \"global_packages_checked\": $GLOBAL_PACKAGES_COUNT,"
    echo "    \"permission_errors\": $PERMISSION_ERRORS"
    echo "  },"
    echo "  \"findings\": {"
    echo "    \"critical\": ["
    
    local first=1
    for finding in "${CRITICAL_FINDINGS[@]}"; do
        if [[ $first -eq 1 ]]; then
            first=0
        else
            echo ","
        fi
        echo -n "      $finding"
    done
    echo ""
    echo "    ],"
    echo "    \"warnings\": ["
    
    first=1
    for finding in "${WARNING_FINDINGS[@]}"; do
        if [[ $first -eq 1 ]]; then
            first=0
        else
            echo ","
        fi
        echo -n "      $finding"
    done
    echo ""
    echo "    ]"
    echo "  },"
    echo "  \"summary\": {"
    echo "    \"critical_threats\": ${#CRITICAL_FINDINGS[@]},"
    echo "    \"warnings\": ${#WARNING_FINDINGS[@]},"
    echo "    \"total_findings\": $((${#CRITICAL_FINDINGS[@]} + ${#WARNING_FINDINGS[@]})),"
    echo "    \"unique_compromised_packages\": $((${#CRITICAL_FINDINGS[@]} + ${#WARNING_FINDINGS[@]}))"
    echo "  }"
    echo "}"
}

generate_json_output > "$OUTPUT_FILE"

echo "✓ Results written to: $OUTPUT_FILE"
echo ""
echo "=========================================="
echo "           SCAN COMPLETE"
echo "=========================================="
echo "Duration: ${DURATION}s"
echo "Summary:"
echo "  - Critical threats: ${#CRITICAL_FINDINGS[@]}"
echo "  - Warnings: ${#WARNING_FINDINGS[@]}"
echo "  - Directories scanned: $DIRS_SCANNED"
echo "  - Packages checked: $PACKAGES_CHECKED"
echo "  - Global packages checked: $GLOBAL_PACKAGES_COUNT"
echo "=========================================="

if [[ ${#CRITICAL_FINDINGS[@]} -gt 0 ]]; then
    echo ""
    echo "⚠️  CRITICAL THREATS DETECTED!"
    echo "Review $OUTPUT_FILE for details"
    exit 2
fi

if [[ ${#WARNING_FINDINGS[@]} -gt 0 ]]; then
    echo ""
    echo "⚠️  WARNINGS DETECTED"
    echo "Review $OUTPUT_FILE for details"
    exit 1
fi

echo ""
echo "✓ No compromised packages found"
exit 0
