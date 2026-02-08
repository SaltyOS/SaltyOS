#!/bin/bash
# SaltyOS SMP Smoke Test
# Boots QEMU with 2 CPUs, captures serial output, checks for SMP-related strings.
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_DIR}/build"
TIMEOUT="${SMP_TIMEOUT:-25}"
SMP_CPUS="${SMP_CPUS:-2}"
IMAGE="${BUILD_DIR}/saltyos.img"
LOG_FILE="$(mktemp /tmp/saltyos-smp-XXXXXX.log)"

# Cleanup on exit
cleanup() {
    rm -f "$LOG_FILE"
    if [[ -n "${QEMU_PID:-}" ]] && kill -0 "$QEMU_PID" 2>/dev/null; then
        kill "$QEMU_PID" 2>/dev/null || true
        wait "$QEMU_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# Colors for output (disabled if not a terminal)
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    NC=''
fi

pass() { echo -e "${GREEN}PASS${NC}: $1"; }
fail() { echo -e "${RED}FAIL${NC}: $1"; }
warn() { echo -e "${YELLOW}WARN${NC}: $1"; }

# Pre-flight checks
if [[ ! -d "$BUILD_DIR" ]]; then
    echo "Build directory not found: ${BUILD_DIR}"
    echo "Run 'just build' first."
    exit 1
fi

if [[ ! -f "$IMAGE" ]]; then
    echo "Disk image not found: ${IMAGE}"
    echo "Run 'just build' first."
    exit 1
fi

if ! command -v qemu-system-x86_64 &>/dev/null; then
    echo "qemu-system-x86_64 not found in PATH."
    exit 1
fi

echo "=== SaltyOS SMP Smoke Test ==="
echo "Image:   ${IMAGE}"
echo "CPUs:    ${SMP_CPUS}"
echo "Timeout: ${TIMEOUT}s"
echo ""

# Run QEMU headless with SMP
qemu-system-x86_64 \
    -machine q35 \
    -cpu qemu64 \
    -smp "$SMP_CPUS" \
    -m 512M \
    -serial file:"$LOG_FILE" \
    -display none \
    -drive file="$IMAGE",format=raw,if=none,id=disk \
    -device ahci,id=ahci \
    -device ide-hd,drive=disk,bus=ahci.0 \
    -no-reboot \
    -no-shutdown &
QEMU_PID=$!

# Wait for timeout or QEMU exit
ELAPSED=0
while kill -0 "$QEMU_PID" 2>/dev/null && [[ $ELAPSED -lt $TIMEOUT ]]; do
    sleep 1
    ELAPSED=$((ELAPSED + 1))
done

# Kill QEMU if still running
if kill -0 "$QEMU_PID" 2>/dev/null; then
    kill "$QEMU_PID" 2>/dev/null || true
    wait "$QEMU_PID" 2>/dev/null || true
fi

# Check results
if [[ ! -s "$LOG_FILE" ]]; then
    fail "No serial output captured (empty log)"
    exit 1
fi

echo "--- Serial output (last 40 lines) ---"
tail -40 "$LOG_FILE"
echo ""
echo "--- Test Results ---"

FAILURES=0

check_string() {
    local label="$1"
    local pattern="$2"
    if grep -qF "$pattern" "$LOG_FILE"; then
        pass "$label"
    else
        fail "$label (expected: \"$pattern\")"
        FAILURES=$((FAILURES + 1))
    fi
}

check_regex() {
    local label="$1"
    local pattern="$2"
    if grep -qE "$pattern" "$LOG_FILE"; then
        pass "$label"
    else
        fail "$label (expected pattern: \"$pattern\")"
        FAILURES=$((FAILURES + 1))
    fi
}

check_absent() {
    local label="$1"
    local pattern="$2"
    if grep -qF "$pattern" "$LOG_FILE"; then
        fail "$label (unexpected: \"$pattern\")"
        FAILURES=$((FAILURES + 1))
    else
        pass "$label"
    fi
}

# Check that SMP initialization started
check_string "SMP AP startup"           "[SMP] Starting Application Processors"
check_string "SMP AP online"            "[SMP] AP is online"
check_string "SMP startup complete"     "[SMP] AP startup complete. Online CPUs:"

# Check that APs actually came up
# AP entry prints "[AP] CPU <N> online" for each non-BSP CPU
for cpu_id in $(seq 1 $((SMP_CPUS - 1))); do
    check_string "AP CPU ${cpu_id} online"  "[AP] CPU ${cpu_id} online"
done

# Also verify boot tests still pass under SMP
check_string "Phase 1: IPC test (SMP)"       "[INIT] Phase 1 IPC test PASSED"
check_string "Phase 2: Fault handling (SMP)"  "[INIT] Phase 2 Fault test PASSED"
check_string "Phase 3: Console (SMP)"         "[INIT] Phase 3 PASSED"
check_string "Phase 4: Servers (SMP)"         "[INIT] Phase 4: All servers spawned!"
check_string "Phase 5: Tests (SMP)"           "[INIT] Phase 5 PASSED"
check_absent "Kernel exceptions (SMP)"        "*** EXCEPTION:"
check_absent "Init failure (SMP)"             "[INIT] FAIL:"

echo ""
if [[ $FAILURES -eq 0 ]]; then
    echo -e "${GREEN}All SMP smoke tests passed.${NC}"
    exit 0
else
    echo -e "${RED}${FAILURES} test(s) failed.${NC}"
    exit 1
fi
