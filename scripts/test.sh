#!/bin/bash
set -e

echo "Testing SaltyOS Phase 1..."
echo

# Build first
if [ ! -f "build/saltyos-uefi.img" ] || [ ! -f "build/saltyos-bios.img" ]; then
    echo "Building..."
    ./scripts/build.sh
    echo
fi

echo "==================================="
echo "Test 1: UEFI Boot"
echo "==================================="
echo "Starting UEFI test (will timeout after 10 seconds)..."
echo
timeout 10 ./scripts/run-qemu-uefi.sh || true

echo
echo
echo "==================================="
echo "Test 2: BIOS Boot"
echo "==================================="
echo "Starting BIOS test (will timeout after 10 seconds)..."
echo
timeout 10 ./scripts/run-qemu-bios.sh || true

echo
echo "==================================="
echo "Tests complete!"
echo "==================================="
echo
echo "Expected output:"
echo "  - UEFI: 'Booted via: UEFI' and 'Hello, SaltyOS!'"
echo "  - BIOS: 'Booted via: BIOS' and 'Hello, SaltyOS!'"
