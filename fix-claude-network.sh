#!/usr/bin/env bash
set -euo pipefail

# Workaround for Tailscale interfering with multi-segment TCP packets.
# Tailscale's kernel-level packet filter silently drops TCP segments beyond the
# first when the payload spans multiple packets. Lowering the interface MTU
# forces TCP to use smaller segments that survive the filter.
#
# The script detects the active default-route interface, lowers its MTU to 1280,
# resets the TCP MSS default to match, verifies Claude Code can reach the API,
# and rolls everything back on failure.

TARGET_MTU=1280
TARGET_MSS=$((TARGET_MTU - 40))  # IP(20) + TCP(20) headers
CLAUDE_TEST_TIMEOUT=30

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*"; }

detect_interface() {
    route -n get default 2>/dev/null | awk '/interface:/{print $2}'
}

get_current_mtu() {
    ifconfig "$1" 2>/dev/null | awk '/mtu/{print $NF}'
}

get_current_mss() {
    sysctl -n net.inet.tcp.mssdflt 2>/dev/null
}

rollback() {
    local iface="$1" orig_mtu="$2" orig_mss="$3"
    warn "Rolling back changes..."
    sudo ifconfig "$iface" mtu "$orig_mtu" 2>/dev/null || true
    sudo sysctl -w net.inet.tcp.mssdflt="$orig_mss" >/dev/null 2>&1 || true
    log "Restored ${iface} MTU=${orig_mtu}, MSS=${orig_mss}"
}

test_claude_connectivity() {
    # POST a body >1300 bytes to confirm multi-segment TCP works
    local payload
    payload=$(python3 -c "
import json, sys
body = json.dumps({
    'model': 'claude-sonnet-4-20250514',
    'max_tokens': 1,
    'messages': [{'role': 'user', 'content': 'x' * 2000}]
})
sys.stdout.write(body)
")
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$CLAUDE_TEST_TIMEOUT" \
        -X POST https://api.anthropic.com/v1/messages \
        -H "Content-Type: application/json" \
        -H "anthropic-version: 2023-06-01" \
        -H "x-api-key: dummy-connectivity-test" \
        -d "$payload" 2>/dev/null) || true

    # 401 = reached the API (auth rejected, but network works)
    [[ "$http_code" == "401" ]]
}

main() {
    local iface orig_mtu orig_mss

    iface=$(detect_interface)
    if [[ -z "$iface" ]]; then
        err "Could not detect default network interface."
        exit 1
    fi

    orig_mtu=$(get_current_mtu "$iface")
    orig_mss=$(get_current_mss)

    log "Interface: ${iface}  MTU: ${orig_mtu}  MSS: ${orig_mss}"

    if [[ "$orig_mtu" -le "$TARGET_MTU" ]]; then
        log "MTU is already ≤${TARGET_MTU}, nothing to do."
    else
        log "Setting ${iface} MTU=${TARGET_MTU} (was ${orig_mtu})"
        sudo ifconfig "$iface" mtu "$TARGET_MTU"
    fi

    if [[ "$orig_mss" -le "$TARGET_MSS" ]]; then
        log "MSS is already ≤${TARGET_MSS}, nothing to do."
    else
        log "Setting TCP MSS=${TARGET_MSS} (was ${orig_mss})"
        sudo sysctl -w net.inet.tcp.mssdflt="$TARGET_MSS" >/dev/null
    fi

    log "Testing connectivity with a multi-segment POST to api.anthropic.com..."
    if test_claude_connectivity; then
        log "Connectivity test passed (got HTTP 401 — network is healthy)."
        echo ""
        log "Summary:"
        log "  Interface ${iface}: MTU ${orig_mtu} → ${TARGET_MTU}"
        log "  TCP MSS: ${orig_mss} → ${TARGET_MSS}"
        echo ""
        warn "These settings do NOT persist across reboots."
        warn "To undo:  sudo ifconfig ${iface} mtu ${orig_mtu} && sudo sysctl -w net.inet.tcp.mssdflt=${orig_mss}"
    else
        err "Connectivity test FAILED — could not reach api.anthropic.com."
        rollback "$iface" "$orig_mtu" "$orig_mss"
        exit 1
    fi
}

main "$@"

# --- What this fixes and why ---
#
# Problem:
#   Tailscale's kernel-level packet filter silently drops TCP segments beyond
#   the first when a payload spans multiple packets. Even though traffic goes
#   through your physical interface (e.g. en19) and not through Tailscale's
#   utun tunnels, Tailscale's network hooks still process every packet. Any
#   HTTPS request with a body larger than ~1300 bytes fails with ECONNRESET
#   because the second TCP segment never arrives at the server.
#
#   Tailscale also sets net.inet.tcp.mssdflt to 512 (should be ~1460), which
#   makes the problem worse by fragmenting even small payloads.
#
#   Affected: Claude Code API calls (~60 KB POST body), telemetry exports
#   (~1.5 KB), and any other large HTTPS POST on the machine.
#   Unaffected: small GETs, DNS, ICMP (ping), curl with tiny payloads.
#
# Fix:
#   Lower the interface MTU to 1280 and the TCP MSS to 1240. This forces TCP
#   to create smaller segments that Tailscale's filter handles correctly.
#
# Why `ifconfig mtu 1280` works but `sysctl mssdflt=1460` alone does not:
#   - sysctl net.inet.tcp.mssdflt sets the *advertised* Maximum Segment Size
#     for new TCP connections. Setting it to 1460 is the correct default for a
#     1500-MTU network, but Tailscale's packet corruption happens regardless
#     of what MSS is negotiated — it drops the 2nd+ segments of any burst.
#   - ifconfig mtu 1280 constrains the entire IP layer. The OS will never
#     produce an IP packet larger than 1280 bytes on that interface, so each
#     TLS record + TCP header fits in a single packet that survives the filter.
#
# Notes:
#   - Settings do NOT persist across reboots or Tailscale reconnects.
#   - MTU 1280 is the IPv6 minimum, so all internet infrastructure supports it.
#   - Throughput drops ~15% due to higher per-packet overhead. Acceptable for
#     dev work; revert if doing bulk transfers.
