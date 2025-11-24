#!/bin/bash
# SHA1-HULUD Scanner - Complete version with 350+ packages
# Scans a Node.js project to detect compromised packages

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Known false positives (legitimate packages with "sha1" in their name)
FALSE_POSITIVES=(
  "@aws-crypto/sha1-browser"
  "@aws-crypto/sha256-browser"
  "@aws-crypto/sha256-js"
  "sha1"
  "sha.js"
)

# Show help
show_help() {
  echo "Usage: $0 <project_directory>"
  echo ""
  echo "Scans a Node.js project to detect packages compromised by SHA1-HULUD pt 2"
  echo ""
  echo "Example:"
  echo "  $0 /path/to/project"
  echo "  $0 ~/Projects/my-project"
  echo ""
  echo "The script uses sha1-hulud-packages.txt file (288+ packages)"
}

# Check if argument provided
if [ $# -eq 0 ]; then
  echo -e "${RED}❌ Error: No directory specified${NC}"
  echo ""
  show_help
  exit 1
fi

PROJECT_DIR="$1"

# Check if directory exists
if [ ! -d "$PROJECT_DIR" ]; then
  echo -e "${RED}❌ Error: Directory '$PROJECT_DIR' does not exist${NC}"
  exit 1
fi

# Check if it's a Node.js project
if [ ! -f "$PROJECT_DIR/package.json" ]; then
  echo -e "${RED}❌ Error: No package.json found in '$PROJECT_DIR'${NC}"
  exit 1
fi

# File containing list of compromised packages
PACKAGES_FILE="$(dirname "$0")/sha1-hulud-packages.txt"

# Load package list
if [ ! -f "$PACKAGES_FILE" ]; then
  echo -e "${RED}❌ Error: Package file not found: $PACKAGES_FILE${NC}"
  echo ""
  echo "Create sha1-hulud-packages.txt in the same directory as this script."
  exit 1
fi

# Read packages (ignore empty lines and comments)
COMPROMISED_PACKAGES=()
while IFS= read -r line; do
  # Ignore comments and empty lines
  [[ "$line" =~ ^#.*$ ]] && continue
  [[ -z "$line" ]] && continue
  COMPROMISED_PACKAGES+=("$line")
done < "$PACKAGES_FILE"

echo ""
echo "🔍 SHA1-HULUD Scanner v2.1"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📁 Project: $PROJECT_DIR"
echo "📋 ${#COMPROMISED_PACKAGES[@]} packages to scan"
echo "📋 ${#FALSE_POSITIVES[@]} known false positives to exclude"
echo ""

# Counters
FOUND=0
FOUND_PACKAGES=()
TOTAL_CHECKS=0

# Scan direct dependencies
scan_package_json() {
  echo "🔎 [1/4] Scanning direct dependencies (package.json)..."

  if [ ! -f "$PROJECT_DIR/package.json" ]; then
    return
  fi

  for package in "${COMPROMISED_PACKAGES[@]}"; do
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

    # Search in dependencies and devDependencies
    if grep -q "\"$package\"" "$PROJECT_DIR/package.json" 2>/dev/null; then
      echo -e "  ${RED}⚠️  FOUND: $package in package.json${NC}"
      FOUND=$((FOUND + 1))
      FOUND_PACKAGES+=("$package (direct)")
    fi
  done

  if [ $FOUND -eq 0 ]; then
    echo -e "  ${GREEN}✓ No compromised packages in direct dependencies${NC}"
  fi
}

# Scan node_modules
scan_node_modules() {
  echo ""
  echo "🔎 [2/4] Scanning node_modules (transitive)..."

  if [ ! -d "$PROJECT_DIR/node_modules" ]; then
    echo -e "  ${YELLOW}⚠️  node_modules not found (run 'npm install' first)${NC}"
    return
  fi

  local found_in_modules=0

  for package in "${COMPROMISED_PACKAGES[@]}"; do
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

    # For scoped packages (@xxx/), search exact folder
    if [[ "$package" == @*/* ]]; then
      if [ -d "$PROJECT_DIR/node_modules/$package" ]; then
        echo -e "  ${RED}🚨 FOUND: $package installed${NC}"
        FOUND=$((FOUND + 1))
        FOUND_PACKAGES+=("$package (transitive)")
        found_in_modules=$((found_in_modules + 1))
      fi
    else
      # For non-scoped packages
      if [ -d "$PROJECT_DIR/node_modules/$package" ]; then
        echo -e "  ${RED}🚨 FOUND: $package installed${NC}"
        FOUND=$((FOUND + 1))
        FOUND_PACKAGES+=("$package (transitive)")
        found_in_modules=$((found_in_modules + 1))
      fi
    fi
  done

  if [ $found_in_modules -eq 0 ]; then
    echo -e "  ${GREEN}✓ No compromised packages installed${NC}"
  fi
}

# Scan lockfiles
scan_lockfiles() {
  echo ""
  echo "🔎 [3/4] Scanning lockfiles..."

  local found_in_locks=0

  # package-lock.json
  if [ -f "$PROJECT_DIR/package-lock.json" ]; then
    echo "  📄 Scanning package-lock.json..."
    for package in "${COMPROMISED_PACKAGES[@]}"; do
      if grep -q "\"$package\"" "$PROJECT_DIR/package-lock.json" 2>/dev/null; then
        echo -e "    ${RED}⚠️  FOUND: $package${NC}"
        FOUND=$((FOUND + 1))
        FOUND_PACKAGES+=("$package (lockfile)")
        found_in_locks=$((found_in_locks + 1))
      fi
    done
  fi

  # yarn.lock
  if [ -f "$PROJECT_DIR/yarn.lock" ]; then
    echo "  📄 Scanning yarn.lock..."
    for package in "${COMPROMISED_PACKAGES[@]}"; do
      if grep -q "$package@" "$PROJECT_DIR/yarn.lock" 2>/dev/null; then
        echo -e "    ${RED}⚠️  FOUND: $package${NC}"
        FOUND=$((FOUND + 1))
        FOUND_PACKAGES+=("$package (lockfile)")
        found_in_locks=$((found_in_locks + 1))
      fi
    done
  fi

  # bun.lock (binary file - use strings)
  if [ -f "$PROJECT_DIR/bun.lock" ]; then
    echo "  📄 Scanning bun.lock..."
    for package in "${COMPROMISED_PACKAGES[@]}"; do
      if strings "$PROJECT_DIR/bun.lock" 2>/dev/null | grep -q "$package"; then
        echo -e "    ${RED}⚠️  FOUND: $package${NC}"
        FOUND=$((FOUND + 1))
        FOUND_PACKAGES+=("$package (lockfile)")
        found_in_locks=$((found_in_locks + 1))
      fi
    done
  fi

  # pnpm-lock.yaml
  if [ -f "$PROJECT_DIR/pnpm-lock.yaml" ]; then
    echo "  📄 Scanning pnpm-lock.yaml..."
    for package in "${COMPROMISED_PACKAGES[@]}"; do
      if grep -q "$package" "$PROJECT_DIR/pnpm-lock.yaml" 2>/dev/null; then
        echo -e "    ${RED}⚠️  FOUND: $package${NC}"
        FOUND=$((FOUND + 1))
        FOUND_PACKAGES+=("$package (lockfile)")
        found_in_locks=$((found_in_locks + 1))
      fi
    done
  fi

  if [ $found_in_locks -eq 0 ]; then
    echo -e "  ${GREEN}✓ No compromised packages in lockfiles${NC}"
  fi
}

# Check if a package is a false positive
is_false_positive() {
  local package="$1"
  for fp in "${FALSE_POSITIVES[@]}"; do
    if [[ "$package" == *"$fp"* ]]; then
      return 0  # True, it's a false positive
    fi
  done
  return 1  # False, not a false positive
}

# Search for SHA1-HULUD markers
scan_sha1_markers() {
  echo ""
  echo "🔎 [4/4] Scanning for SHA1-HULUD markers..."

  local found_markers=0
  local false_positive_count=0

  # Search for packages with "sha1" in their name in package-lock.json
  if [ -f "$PROJECT_DIR/package-lock.json" ]; then
    local sha1_packages=$(grep -oE '"[^"]*sha1[^"]*"' "$PROJECT_DIR/package-lock.json" 2>/dev/null | sed 's/"//g' | sort -u | grep -v "sha512\|sha256")

    if [ -n "$sha1_packages" ]; then
      echo "  📄 Checking packages with 'sha1' in name (package-lock.json):"
      while IFS= read -r pkg; do
        if [ -n "$pkg" ] && [[ "$pkg" == *"sha1"* ]]; then
          if is_false_positive "$pkg"; then
            echo -e "    ${YELLOW}ℹ️  $pkg (legitimate package - skipped)${NC}"
            false_positive_count=$((false_positive_count + 1))
          else
            echo -e "    ${RED}🚨 $pkg (SUSPICIOUS)${NC}"
            found_markers=$((found_markers + 1))
            FOUND=$((FOUND + 1))
            FOUND_PACKAGES+=("$pkg (SHA1 in package name - package-lock.json)")
          fi
        fi
      done <<< "$sha1_packages"
    fi
  fi

  # Search for packages with "sha1" in their name in yarn.lock
  if [ -f "$PROJECT_DIR/yarn.lock" ]; then
    local sha1_packages=$(grep -E "sha1" "$PROJECT_DIR/yarn.lock" 2>/dev/null | grep -oE '^[^@]*@[^@]+@|^@[^"]+@' | sed 's/@$//' | grep "sha1" | sort -u | grep -v "sha512\|sha256")

    if [ -n "$sha1_packages" ]; then
      echo "  📄 Checking packages with 'sha1' in name (yarn.lock):"
      while IFS= read -r pkg; do
        if [ -n "$pkg" ] && [[ "$pkg" == *"sha1"* ]]; then
          if is_false_positive "$pkg"; then
            echo -e "    ${YELLOW}ℹ️  $pkg (legitimate package - skipped)${NC}"
            false_positive_count=$((false_positive_count + 1))
          else
            echo -e "    ${RED}🚨 $pkg (SUSPICIOUS)${NC}"
            found_markers=$((found_markers + 1))
            FOUND=$((FOUND + 1))
            FOUND_PACKAGES+=("$pkg (SHA1 in package name - yarn.lock)")
          fi
        fi
      done <<< "$sha1_packages"
    fi
  fi

  # Search for packages with "sha1" in their name in bun.lock
  if [ -f "$PROJECT_DIR/bun.lock" ]; then
    local sha1_packages=$(strings "$PROJECT_DIR/bun.lock" 2>/dev/null | grep "sha1" | grep -oE '@[a-zA-Z0-9_/-]+sha1[a-zA-Z0-9_-]*|sha1[a-zA-Z0-9_-]+' | sort -u | grep -v "sha512\|sha256")

    if [ -n "$sha1_packages" ]; then
      echo "  📄 Checking packages with 'sha1' in name (bun.lock):"
      while IFS= read -r pkg; do
        if [ -n "$pkg" ] && [[ "$pkg" == *"sha1"* ]]; then
          if is_false_positive "$pkg"; then
            echo -e "    ${YELLOW}ℹ️  $pkg (legitimate package - skipped)${NC}"
            false_positive_count=$((false_positive_count + 1))
          else
            echo -e "    ${RED}🚨 $pkg (SUSPICIOUS)${NC}"
            found_markers=$((found_markers + 1))
            FOUND=$((FOUND + 1))
            FOUND_PACKAGES+=("$pkg (SHA1 in package name - bun.lock)")
          fi
        fi
      done <<< "$sha1_packages"
    fi
  fi

  # Search for packages with "sha1" in their name in pnpm-lock.yaml
  if [ -f "$PROJECT_DIR/pnpm-lock.yaml" ]; then
    local sha1_packages=$(grep "sha1" "$PROJECT_DIR/pnpm-lock.yaml" 2>/dev/null | grep -oE '[^/]+sha1[^:]*' | sort -u | grep -v "sha512\|sha256")

    if [ -n "$sha1_packages" ]; then
      echo "  📄 Checking packages with 'sha1' in name (pnpm-lock.yaml):"
      while IFS= read -r pkg; do
        if [ -n "$pkg" ] && [[ "$pkg" == *"sha1"* ]]; then
          if is_false_positive "$pkg"; then
            echo -e "    ${YELLOW}ℹ️  $pkg (legitimate package - skipped)${NC}"
            false_positive_count=$((false_positive_count + 1))
          else
            echo -e "    ${RED}🚨 $pkg (SUSPICIOUS)${NC}"
            found_markers=$((found_markers + 1))
            FOUND=$((FOUND + 1))
            FOUND_PACKAGES+=("$pkg (SHA1 in package name - pnpm-lock.yaml)")
          fi
        fi
      done <<< "$sha1_packages"
    fi
  fi

  if [ $found_markers -eq 0 ]; then
    if [ $false_positive_count -gt 0 ]; then
      echo -e "  ${GREEN}✓ No suspicious SHA1 markers (${false_positive_count} legitimate packages excluded)${NC}"
    else
      echo -e "  ${GREEN}✓ No SHA1-HULUD markers detected${NC}"
    fi
  fi
}

# Run scans
scan_package_json
scan_node_modules
scan_lockfiles
scan_sha1_markers

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Final result
if [ $FOUND -eq 0 ]; then
  echo -e "${GREEN}✅ NO COMPROMISE DETECTED${NC}"
  echo ""
  echo "Your project is clean — no SHA1-HULUD packages found."
  echo ""
  echo "📊 Statistics:"
  echo "   • ${#COMPROMISED_PACKAGES[@]} packages scanned"
  echo "   • 0 compromised packages"
  echo ""
  exit 0
else
  echo -e "${RED}🚨 $FOUND COMPROMISED PACKAGE(S) DETECTED${NC}"
  echo ""
  echo "📦 Packages found:"
  for pkg in "${FOUND_PACKAGES[@]}"; do
    echo "   • $pkg"
  done
  echo ""
  echo "⚠️  IMMEDIATE ACTION REQUIRED:"
  echo ""
  echo "   1. 🛑 STOP all builds/CI immediately"
  echo "   2. 🔒 Isolate CI runners (if self-hosted)"
  echo "   3. 🔑 Rotate ALL sensitive keys:"
  echo "      • GitHub tokens (PAT, fine-grained, App)"
  echo "      • AWS credentials (if non-OIDC)"
  echo "      • NPM tokens"
  echo "      • API keys (PostHog, etc.)"
  echo "   4. 🗑  Delete node_modules and lockfiles"
  echo "   5. 📝 Update dependencies"
  echo "   6. 🔍 Audit CI logs from last 48 hours"
  echo ""
  echo "📚 More info: https://helixguard.ai/blog/malicious-sha1hulud-2025-11-24"
  echo ""
  exit 1
fi
