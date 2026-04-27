#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  STORM_VX — One-Click Pipeline Runner
#  FINDER → TESTER automated attack pipeline
#
#  Usage:
#    bash run.sh https://target.com
#    bash run.sh https://target.com --deep --dns
#    bash run.sh                          (will prompt for URL)
#
#  FOR AUTHORIZED TESTING ONLY!
# ═══════════════════════════════════════════════════════════════════════════════

set -e

# ─── Colors ────────────────────────────────────────────────────────────────────
R='\033[91m'; G='\033[92m'; Y='\033[93m'; B='\033[94m'
M='\033[95m'; CY='\033[96m'; W='\033[97m'; BD='\033[1m'
DM='\033[2m'; RS='\033[0m'

# ─── Banner ────────────────────────────────────────────────────────────────────
show_banner() {
    echo ""
    echo -e "  ${BD}${R}╔═══════════════════════════════════════════════════════╗${RS}"
    echo -e "  ${BD}${R}║          STORM_VX — Attack Pipeline Runner            ║${RS}"
    echo -e "  ${BD}${R}║     FINDER (Recon) → TESTER (Attack)                 ║${RS}"
    echo -e "  ${BD}${R}╚═══════════════════════════════════════════════════════╝${RS}"
    echo ""
}

# ─── Parse Arguments ──────────────────────────────────────────────────────────
TARGET_URL=""
FINDER_FLAGS=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --deep|--dns|--subdomains)
            FINDER_FLAGS="$FINDER_FLAGS $1"
            shift
            ;;
        --output)
            shift
            PROFILE_OUTPUT="$1"
            shift
            ;;
        --max-workers)
            shift
            MAX_WORKERS="$1"
            shift
            ;;
        --step)
            shift
            STEP_OVERRIDE="$1"
            shift
            ;;
        --crash-mode)
            CRASH_MODE=1
            shift
            ;;
        http://*|https://*)
            TARGET_URL="$1"
            shift
            ;;
        *)
            # Treat as URL if it looks like a domain
            if [[ "$1" == *.* ]]; then
                TARGET_URL="$1"
            else
                echo -e "  ${R}[!] Unknown option: $1${RS}"
            fi
            shift
            ;;
    esac
done

# ─── Interactive URL Prompt ───────────────────────────────────────────────────
if [[ -z "$TARGET_URL" ]]; then
    show_banner
    echo -ne "  ${CY}Enter target URL: ${RS}"
    read -r TARGET_URL
    if [[ -z "$TARGET_URL" ]]; then
        echo -e "  ${R}[ERROR] No URL provided. Exiting.${RS}"
        exit 1
    fi
fi

# Auto-add https:// if missing
if [[ ! "$TARGET_URL" =~ ^https?:// ]]; then
    TARGET_URL="https://${TARGET_URL}"
fi

# ─── Config ───────────────────────────────────────────────────────────────────
PROFILE_OUTPUT="${PROFILE_OUTPUT:-VF_PROFILE.json}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Resolve Python command (python3 or python)
PYTHON=""
if command -v python3 &>/dev/null; then
    PYTHON=python3
elif command -v python &>/dev/null; then
    PYTHON=python
else
    echo -e "  ${R}[ERROR] Python not found! Install Python 3.${RS}"
    exit 1
fi

# ─── Check Files ──────────────────────────────────────────────────────────────
if [[ ! -f "${SCRIPT_DIR}/VF_FINDER.py" ]]; then
    echo -e "  ${R}[ERROR] VF_FINDER.py not found in ${SCRIPT_DIR}${RS}"
    exit 1
fi
if [[ ! -f "${SCRIPT_DIR}/VF_TESTER.py" ]]; then
    echo -e "  ${R}[ERROR] VF_TESTER.py not found in ${SCRIPT_DIR}${RS}"
    exit 1
fi

# ─── Phase 1: Run FINDER ─────────────────────────────────────────────────────
echo ""
echo -e "  ${BD}${CY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RS}"
echo -e "  ${BD}${Y}[PHASE 1] Running VF_FINDER — Reconnaissance${RS}"
echo -e "  ${BD}${CY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RS}"
echo -e "  ${W}Target: ${TARGET_URL}${RS}"
echo ""

cd "$SCRIPT_DIR"

$PYTHON VF_FINDER.py "$TARGET_URL" $FINDER_FLAGS --output "$PROFILE_OUTPUT"

# Check if profile was created
if [[ ! -f "$PROFILE_OUTPUT" ]]; then
    echo -e "  ${R}[ERROR] Profile file not created! FINDER may have failed.${RS}"
    exit 1
fi

echo ""
echo -e "  ${G}[✓] Profile saved to: ${PROFILE_OUTPUT}${RS}"
echo ""

# ─── Phase 2: Run TESTER ─────────────────────────────────────────────────────
echo -e "  ${BD}${CY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RS}"
echo -e "  ${BD}${R}[PHASE 2] Running VF_TESTER — Attack${RS}"
echo -e "  ${BD}${CY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RS}"
echo -e "  ${W}Profile: ${PROFILE_OUTPUT}${RS}"
echo ""

# Build TESTER command
TESTER_CMD="$PYTHON VF_TESTER.py --profile $PROFILE_OUTPUT"

if [[ -n "$MAX_WORKERS" ]]; then
    TESTER_CMD="$TESTER_CMD --max-workers $MAX_WORKERS"
fi
if [[ -n "$STEP_OVERRIDE" ]]; then
    TESTER_CMD="$TESTER_CMD --step $STEP_OVERRIDE"
fi
if [[ -n "$CRASH_MODE" ]]; then
    TESTER_CMD="$TESTER_CMD --crash-mode"
fi

# Run TESTER
$TESTER_CMD

echo ""
echo -e "  ${BD}${G}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RS}"
echo -e "  ${BD}${G}[DONE] Pipeline completed.${RS}"
echo -e "  ${BD}${G}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RS}"
