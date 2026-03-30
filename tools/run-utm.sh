#!/usr/bin/env bash
# tools/run-utm.sh - Launch SaltyOS through UTM on macOS.
#
# Usage: tools/run-utm.sh <build-dir> [options]
#
# Options:
#   --arch ARCH       Target architecture (x86_64 or aarch64)
#   --mem SIZE        Memory size (default: 512M)
#   --smp N           CPU count (default: 1)
#   --debug           Enable QEMU debug logging (-d int,cpu_reset -D qemu.log)
#   --headless        Print the serial TCP endpoint and exit without activating UTM
#   --utm-name NAME   Override the UTM VM name (default: SaltyOS-<arch>)
#   --no-net          Skip network device creation
#   --net-mode MODE   shared (default for user/vmnet-shared), bridged
#   --vmnet-ifname IF Host interface for bridged mode
#   --hvf             Enable Hypervisor.framework acceleration (default)
#   --no-hvf          Disable HVF (use TCG emulation)
#   --disk FILE       Override boot disk path
set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }

usage() {
    sed -n '3,15p' "$0" | sed 's/^# \?//'
    exit 1
}

pick_tcp_port() {
    local seed="$1"
    local hash
    hash="$(printf '%s' "$seed" | cksum | awk '{print $1}')"
    echo $((43000 + (hash % 2000)))
}

abspath() {
    local path="$1"
    if [[ "$path" == /* ]]; then
        printf '%s\n' "$path"
        return
    fi
    printf '%s/%s\n' "$(cd "$(dirname "$path")" && pwd -P)" "$(basename "$path")"
}

escape_applescript() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    printf '%s' "$s"
}

mem_to_mib() {
    local value="$1"
    if [[ "$value" =~ ^([0-9]+)([KkMmGg])?$ ]]; then
        local num="${BASH_REMATCH[1]}"
        case "${BASH_REMATCH[2]:-M}" in
            K|k) echo $(((num + 1023) / 1024)) ;;
            M|m) echo "$num" ;;
            G|g) echo $((num * 1024)) ;;
        esac
    else
        die "unsupported memory size: $value"
    fi
}

generate_mac() {
    local seed="$1"
    local crc1 crc2 _
    read -r crc1 _ < <(printf '%s' "$seed" | cksum)
    read -r crc2 _ < <(printf '%s' "${seed}:saltyos" | cksum)
    printf '%02X:%02X:%02X:%02X:%02X:%02X\n' \
        0x52 0x54 \
        $(( (crc1 >> 24) & 0xff )) \
        $(( (crc1 >> 16) & 0xff )) \
        $(( (crc2 >> 24) & 0xff )) \
        $(( (crc2 >> 16) & 0xff ))
}

# --- Parse arguments ---
[[ $# -lt 1 ]] && usage
BUILD_DIR="$1"; shift

ARCH="" MEM="512M" SMP="1" DEBUG=false HEADLESS=false UEFI=false UTM_NAME=""
NO_NET=false NET_MODE="user" VMNET_IFNAME="" DISK="" USE_HVF=true

while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch)         ARCH="${2:?--arch requires a value}"; shift 2 ;;
        --mem)          MEM="${2:?--mem requires a value}"; shift 2 ;;
        --smp)          SMP="${2:?--smp requires a value}"; shift 2 ;;
        --debug)        DEBUG=true; shift ;;
        --headless)     HEADLESS=true; shift ;;
        --uefi)         UEFI=true; shift ;;
        --utm-name)     UTM_NAME="${2:?--utm-name requires a value}"; shift 2 ;;
        --no-net)       NO_NET=true; shift ;;
        --net-mode)     NET_MODE="${2:?--net-mode requires a value}"; shift 2 ;;
        --vmnet-ifname) VMNET_IFNAME="${2:?--vmnet-ifname requires a value}"; shift 2 ;;
        --hvf)          USE_HVF=true; shift ;;
        --no-hvf)       USE_HVF=false; shift ;;
        --disk)         DISK="${2:?--disk requires a value}"; shift 2 ;;
        *)              die "unknown option: $1" ;;
    esac
done

[[ "$(uname -s)" == "Darwin" ]] || die "only supported on macOS"
command -v osascript >/dev/null 2>&1 || die "osascript not found"
[[ -z "$ARCH" ]] && ARCH="x86_64"
[[ "$ARCH" == "x86_64" || "$ARCH" == "aarch64" ]] || die "unsupported architecture: $ARCH"
[[ -n "$UTM_NAME" ]] || UTM_NAME="SaltyOS-$ARCH"

UTM_APP="${UTM_APP:-}"
if [[ -z "$UTM_APP" ]]; then
    for cand in /Applications/UTM.app "$HOME/Applications/UTM.app"; do
        [[ -d "$cand" ]] && { UTM_APP="$cand"; break; }
    done
fi
[[ -n "$UTM_APP" && -d "$UTM_APP" ]] || die "UTM.app not found; set UTM_APP or install UTM"


DEFAULT_IMG="saltyos.img"
$UEFI && DEFAULT_IMG="saltyos-uefi.img"
BOOT_DISK="$(abspath "${DISK:-$BUILD_DIR/$DEFAULT_IMG}")"
[[ -f "$BOOT_DISK" ]] || die "boot disk not found: $BOOT_DISK"

MEM_MIB="$(mem_to_mib "$MEM")"
CONFIG_SERIAL_PORT="${UTM_SERIAL_PORT:-$(pick_tcp_port "$UTM_NAME")}"
CONFIG_MAC_ADDRESS="${UTM_MAC_ADDRESS:-$(generate_mac "$UTM_NAME:$ARCH:$NET_MODE")}"
QEMU_DEBUG_FLAGS="${UTM_QEMU_DEBUG_FLAGS:-int,cpu_reset}"

# --- Architecture-specific settings ---
if [[ "$ARCH" == "x86_64" ]]; then
    QEMU_TARGET="q35"
    QEMU_CPU="default"
    DISPLAY_HW="virtio-vga"
    PS2=true
else
    QEMU_TARGET="virt"
    if $USE_HVF; then
        # HVF executes on the host CPU rather than emulating a fixed core
        # model. On Apple Silicon, forcing cortex-a72 can trip QEMU's HVF
        # backend assertions; use the host CPU model when acceleration is on.
        QEMU_CPU="host"
    else
        QEMU_CPU="cortex-a72"
    fi
    DISPLAY_HW="virtio-ramfb"
    PS2=false
fi

# --- Network ---
NET_MODE_PLIST="Shared"
NET_HW="virtio-net-pci"
NET_ENABLED=true
if $NO_NET; then
    NET_ENABLED=false
else
    case "$NET_MODE" in
        user|vmnet-shared) NET_MODE_PLIST="Shared" ;;
        vmnet-bridged)
            [[ -n "$VMNET_IFNAME" ]] || die "--vmnet-ifname required for bridged"
            NET_MODE_PLIST="Bridged"
            ;;
        *) die "unsupported net mode: $NET_MODE" ;;
    esac
fi

# --- Remove existing UTM VM (delete also removes the .utm bundle on disk) ---
APP_NAME="$(basename "$UTM_APP" .app)"
VM_NAME_ESC="$(escape_applescript "$UTM_NAME")"

osascript <<OSA
tell application "$APP_NAME"
    set vmName to "$VM_NAME_ESC"
    if exists virtual machine named vmName then
        set vm to virtual machine named vmName
        if status of vm is not stopped then
            stop vm by force
            repeat 20 times
                if status of vm is stopped then exit repeat
                delay 0.25
            end repeat
        end if
        delete vm
        delay 0.5
    end if
end tell
OSA

# --- Locate / create UTM bundle ---
UTM_BUNDLE="$BUILD_DIR/$UTM_NAME.utm"
UTM_DATA="$UTM_BUNDLE/Data"
DISK_NAME="saltyos.img"

mkdir -p "$UTM_DATA"
cp -cf "$BOOT_DISK" "$UTM_DATA/$DISK_NAME" 2>/dev/null || cp -f "$BOOT_DISK" "$UTM_DATA/$DISK_NAME"
QEMU_LOG_PATH="$(abspath "${UTM_QEMU_LOG:-$UTM_DATA/qemu.log}")"
QEMU_DEBUG_LOG_PLIST="<false/>"
QEMU_ADDITIONAL_ARGS="<array/>"
QEMU_ARG_ITEMS=""
if [[ "$ARCH" == "aarch64" ]]; then
    QEMU_ARG_ITEMS="$QEMU_ARG_ITEMS
            <string>-machine</string>
            <string>virt,gic-version=3</string>"
fi
if $DEBUG; then
    QEMU_DEBUG_LOG_PLIST="<true/>"
    QEMU_ARG_ITEMS="$QEMU_ARG_ITEMS
            <string>-d</string>
            <string>$QEMU_DEBUG_FLAGS</string>
            <string>-D</string>
            <string>$QEMU_LOG_PATH</string>"
fi
if [[ -n "$QEMU_ARG_ITEMS" ]]; then
    QEMU_ADDITIONAL_ARGS="
        <array>$QEMU_ARG_ITEMS
        </array>"
fi

# --- Generate config.plist ---
NET_SECTION=""
if $NET_ENABLED; then
    NET_SECTION="
    <array>
        <dict>
            <key>Hardware</key><string>$NET_HW</string>
            <key>Mode</key><string>$NET_MODE_PLIST</string>
            <key>MacAddress</key><string>$CONFIG_MAC_ADDRESS</string>
            <key>PortForward</key><array/>
            <key>IsolateFromHost</key><false/>
        </dict>
    </array>"
else
    NET_SECTION="<array/>"
fi

cat > "$UTM_BUNDLE/config.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>ConfigurationVersion</key><integer>4</integer>
    <key>Backend</key><string>QEMU</string>
    <key>Information</key>
    <dict>
        <key>Name</key><string>$UTM_NAME</string>
        <key>UUID</key><string>$(uuidgen)</string>
        <key>IconCustom</key><false/>
    </dict>
    <key>System</key>
    <dict>
        <key>Architecture</key><string>$ARCH</string>
        <key>Target</key><string>$QEMU_TARGET</string>
        <key>CPU</key><string>$QEMU_CPU</string>
        <key>CPUCount</key><integer>$SMP</integer>
        <key>MemorySize</key><integer>$MEM_MIB</integer>
        <key>ForceMulticore</key><false/>
        <key>JITCacheSize</key><integer>0</integer>
        <key>CPUFlagsAdd</key><array/>
        <key>CPUFlagsRemove</key><array/>
    </dict>
    <key>QEMU</key>
    <dict>
        <key>PS2Controller</key><$( $PS2 && echo true || echo false )/>
        <key>Hypervisor</key><$( $USE_HVF && echo true || echo false )/>
        <key>UEFIBoot</key><$( $UEFI && echo true || echo false )/>
        <key>RNGDevice</key><true/>
        <key>BalloonDevice</key><false/>
        <key>TPMDevice</key><false/>
        <key>DebugLog</key>$QEMU_DEBUG_LOG_PLIST
        <key>RTCLocalTime</key><false/>
        <key>TSO</key><false/>
        <key>AdditionalArguments</key>$QEMU_ADDITIONAL_ARGS
    </dict>
    <key>Display</key>
    <array>
        <dict>
            <key>Hardware</key><string>$DISPLAY_HW</string>
            <key>DynamicResolution</key><true/>
            <key>NativeResolution</key><false/>
            <key>UpscalingFilter</key><string>Nearest</string>
            <key>DownscalingFilter</key><string>Linear</string>
        </dict>
    </array>
    <key>Serial</key>
    <array>
        <dict>
            <key>Mode</key><string>TcpServer</string>
            <key>Target</key><string>Auto</string>
            <key>TcpPort</key><integer>$CONFIG_SERIAL_PORT</integer>
            <key>WaitForConnection</key><true/>
            <key>RemoteConnectionAllowed</key><false/>
        </dict>
    </array>
    <key>Network</key>
    $NET_SECTION
    <key>Drive</key>
    <array>
        <dict>
            <key>Interface</key><string>VirtIO</string>
            <key>Identifier</key><string>$(uuidgen)</string>
            <key>InterfaceVersion</key><integer>1</integer>
            <key>ReadOnly</key><false/>
            <key>ImageName</key><string>$DISK_NAME</string>
            <key>ImageType</key><string>Disk</string>
        </dict>
    </array>
    <key>Sound</key><array/>
    <key>Input</key>
    <dict>
        <key>UsbSharing</key><false/>
        <key>UsbBusSupport</key><string>3.0</string>
        <key>MaximumUsbShare</key><integer>3</integer>
    </dict>
    <key>Sharing</key>
    <dict>
        <key>DirectoryShareReadOnly</key><false/>
        <key>ClipboardSharing</key><true/>
        <key>DirectoryShareMode</key><string>WebDAV</string>
    </dict>
</dict>
</plist>
PLIST

# --- Register and start VM via AppleScript ---
UTM_BUNDLE_ABS="$(abspath "$UTM_BUNDLE")"
SERIAL_PORT="$(osascript <<OSA
tell application "$APP_NAME"
    set vmName to "$VM_NAME_ESC"
    set bundlePath to POSIX file "$(escape_applescript "$UTM_BUNDLE_ABS")"

    do shell script "open -a '$APP_NAME' " & quoted form of POSIX path of bundlePath
    repeat 40 times
        delay 0.25
        if exists virtual machine named vmName then exit repeat
    end repeat

    if not (exists virtual machine named vmName) then
        error "VM '" & vmName & "' failed to register in UTM."
    end if

    set vm to virtual machine named vmName

    repeat with i from 1 to count of (serial ports of vm)
        set sp to item i of (serial ports of vm)
        if interface of sp is tcp then
            set tcpPort to port of sp
            if tcpPort is not 0 then
                return tcpPort as text
            end if
        end if
    end repeat

    return "$CONFIG_SERIAL_PORT"
end tell
OSA
)"

SERIAL_HOST="127.0.0.1"
SERIAL_ENDPOINT="$SERIAL_HOST:$SERIAL_PORT"

start_vm() {
    osascript >/dev/null <<OSA
tell application "$APP_NAME"
    start virtual machine named "$VM_NAME_ESC"
end tell
OSA
}

if $HEADLESS; then
    start_vm &
    echo "UTM VM starting: $UTM_NAME"
    echo "Serial TCP: $SERIAL_ENDPOINT"
    echo "Guest boot waits until a client connects."
    exit 0
fi

osascript >/dev/null <<OSA
tell application "$APP_NAME"
    activate
end tell
OSA

start_vm &

echo "UTM VM starting: $UTM_NAME" >&2
echo "Serial TCP: $SERIAL_ENDPOINT" >&2
exec python3 -u -c '
import os, sys, tty, termios, select, signal, socket, time

deadline = time.monotonic() + 30.0
sock = None
while time.monotonic() < deadline:
    try:
        sock = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=1.0)
        break
    except OSError:
        time.sleep(0.1)

if sock is None:
    raise SystemExit(f"error: timed out waiting for serial TCP at {sys.argv[1]}:{sys.argv[2]}")

sock.setblocking(False)
sock_fd = sock.fileno()

old_attrs = termios.tcgetattr(sys.stdin)
tty.setraw(sys.stdin)

def restore(signum=None, frame=None):
    termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_attrs)
    raise SystemExit(0)
signal.signal(signal.SIGINT, restore)
signal.signal(signal.SIGTERM, restore)

try:
    while True:
        rlist, _, _ = select.select([sys.stdin, sock_fd], [], [])
        if sys.stdin in rlist:
            d = os.read(sys.stdin.fileno(), 4096)
            if not d: break
            sock.sendall(d)
        if sock_fd in rlist:
            d = os.read(sock_fd, 4096)
            if not d: break
            os.write(sys.stdout.fileno(), d.replace(b"\n", b"\r\n"))
except OSError:
    pass
finally:
    termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_attrs)
' "$SERIAL_HOST" "$SERIAL_PORT"
