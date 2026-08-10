#!/bin/bash
set -Eeuo pipefail
umask 077

CONFIG_DIR=/etc/printproxy
CONFIG_FILE=$CONFIG_DIR/printproxy.conf
STATE_FILE=$CONFIG_DIR/install-state
ARTIFACT_MANIFEST=$CONFIG_DIR/artifacts.sha256
LOCK_FILE=/run/lock/printproxy-install.lock
BACKUP_ROOT=/var/backups/printproxy
PURGE_CONFIG=no
PURGE_DATA=no
ACK_DATA=no

usage() {
    cat <<'EOF'
Usage: sudo ./uninstall.sh [--purge-config] [--purge-data --i-understand-data-loss]

Default behavior removes the running proxy software, units, VIP owned by the
installer and scoped firewall table. It preserves archives, spool, configuration
and the HMAC key so historical verification remains possible.
EOF
}

for argument in "$@"; do
    case "$argument" in
        --purge-config) PURGE_CONFIG=yes ;;
        --purge-data) PURGE_DATA=yes ;;
        --i-understand-data-loss) ACK_DATA=yes ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $argument" >&2; usage >&2; exit 2 ;;
    esac
done

[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
exec 9>"$LOCK_FILE"
flock -n 9 || { echo 'Another install/uninstall operation is active.' >&2; exit 1; }

if [[ $PURGE_DATA == yes && $ACK_DATA != yes ]]; then
    echo 'REFUSED: --purge-data requires --i-understand-data-loss.' >&2
    exit 2
fi

conf_get() {
    local key=$1 file=$2
    [[ -r $file ]] || return 0
    awk -v wanted="$key" '
        /^[[:space:]]*#/ || /^[[:space:]]*$/ {next}
        {p=index($0,"="); if(!p)next; k=substr($0,1,p-1); gsub(/^[[:space:]]+|[[:space:]]+$/,"",k);
         if(k==wanted){v=substr($0,p+1); gsub(/^[[:space:]]+|[[:space:]]+$/,"",v); gsub(/^['\''\"]|['\''\"]$/,"",v); print v; exit}}
    ' "$file"
}

PRINTER_IP=$(conf_get PRINTER_IP "$CONFIG_FILE")
PRINTER_PORT=$(conf_get PRINTER_PORT "$CONFIG_FILE")
echo "IMPORTANT: first restore the management software printer destination to ${PRINTER_IP:-10.1.2.200}:${PRINTER_PORT:-9100}."
echo 'Stopping the proxy before that change makes printing unavailable.'

install -d -m 0700 -o root -g root "$BACKUP_ROOT"
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
recovery_backup=$(mktemp -d "$BACKUP_ROOT/uninstall-$timestamp.XXXXXX")
chmod 0700 "$recovery_backup"
chown root:root "$recovery_backup"
if [[ -d $CONFIG_DIR ]]; then
    cp -a -- "$CONFIG_DIR" "$recovery_backup/config"
fi

if [[ ! -f $STATE_FILE || -L $STATE_FILE ]]; then
    echo "Installer state is missing/unsafe. Safe mode: no service, VIP, firewall or files were removed." >&2
    echo "Recovery copy: $recovery_backup" >&2
    exit 1
fi

expected_hash() {
    local target=$1
    [[ -f $ARTIFACT_MANIFEST && ! -L $ARTIFACT_MANIFEST ]] || return 1
    awk -v target="$target" '$2 == target { print $1; exit }' "$ARTIFACT_MANIFEST"
}

artifact_matches() {
    local target=$1 expected actual
    expected=$(expected_hash "$target" || true)
    [[ -n $expected && -f $target && ! -L $target ]] || return 1
    actual=$(sha256sum -- "$target" | awk '{print $1}')
    [[ $actual == "$expected" ]]
}

VIP_OWNED=$(conf_get VIP_OWNED "$STATE_FILE")
VIP=$(conf_get VIP "$STATE_FILE")
FIREWALL_OWNED=$(conf_get FIREWALL_OWNED "$STATE_FILE")
if [[ $VIP_OWNED == yes ]] && ! artifact_matches /usr/local/libexec/printproxy-vip; then
    echo 'Owned VIP helper is missing or modified; refusing to execute it as root. Remove the exact VIP manually, then retry.' >&2
    exit 1
fi
if [[ $FIREWALL_OWNED == yes ]] && ! artifact_matches /usr/local/libexec/printproxy-firewall; then
    echo 'Owned firewall helper is missing or modified; refusing to execute it as root. Remove the exact table manually, then retry.' >&2
    exit 1
fi

systemctl stop printproxy.service 2>/dev/null || true
if systemctl is-active --quiet printproxy.service 2>/dev/null; then
    echo 'Proxy did not stop cleanly; refusing to continue.' >&2
    exit 1
fi
systemctl disable printproxy.service printproxy-firewall.service printproxy-vip.service printproxy-vip-watch.timer >/dev/null 2>&1 || true
systemctl stop printproxy-vip-watch.timer printproxy-vip-watch.service 2>/dev/null || true
systemctl stop printproxy-firewall.service 2>/dev/null || true
systemctl stop printproxy-vip.service 2>/dev/null || true

# If units were unavailable, helpers still remove only resources explicitly owned
# in the root-only installer state. No routes, gateways or primary IPs are touched.
if [[ -x /usr/local/libexec/printproxy-firewall ]]; then
    /usr/local/libexec/printproxy-firewall down 2>/dev/null || true
fi
if [[ -x /usr/local/libexec/printproxy-vip ]]; then
    /usr/local/libexec/printproxy-vip down 2>/dev/null || true
fi

if [[ $VIP_OWNED == yes && -n $VIP ]] && ip -o -4 addr show | awk -v ip="$VIP" '$4 ~ ("^" ip "/") {found=1} END {exit !found}'; then
    echo "Owned VIP $VIP could not be removed; helpers and installer state are being preserved." >&2
    exit 1
fi
if [[ $FIREWALL_OWNED == yes ]] && command -v nft >/dev/null 2>&1 && nft list table inet printproxy_filter >/dev/null 2>&1; then
    echo 'Owned nftables table could not be removed; helpers and installer state are being preserved.' >&2
    exit 1
fi

remove_owned_file() {
    local target=$1 destination
    [[ -e $target || -L $target ]] || return 0
    if artifact_matches "$target"; then
        rm -f -- "$target"
        return 0
    fi
    destination="$recovery_backup/modified-artifacts${target}"
    install -d -m 0700 -o root -g root "$(dirname -- "$destination")"
    mv -- "$target" "$destination"
    echo "Preserved modified/untracked artifact: $target -> $destination" >&2
}

for target in \
    /etc/systemd/system/printproxy.service \
    /etc/systemd/system/printproxy-vip.service \
    /etc/systemd/system/printproxy-firewall.service \
    /etc/systemd/system/printproxy-vip-watch.service \
    /etc/systemd/system/printproxy-vip-watch.timer \
    /etc/systemd/system/printproxy.service.d/paths.conf \
    /etc/logrotate.d/printproxy \
    /usr/local/libexec/printproxy-vip \
    /usr/local/libexec/printproxy-firewall; do
    remove_owned_file "$target"
done

if [[ -L /usr/local/sbin/printproxyctl && $(readlink -- /usr/local/sbin/printproxyctl) == /opt/printproxy/printproxyctl.py ]]; then
    rm -f -- /usr/local/sbin/printproxyctl
elif [[ -e /usr/local/sbin/printproxyctl || -L /usr/local/sbin/printproxyctl ]]; then
    remove_owned_file /usr/local/sbin/printproxyctl
fi

if [[ -f $ARTIFACT_MANIFEST && ! -L $ARTIFACT_MANIFEST ]]; then
    while IFS= read -r target; do
        case "$target" in
            /opt/printproxy/*) remove_owned_file "$target" ;;
        esac
    done < <(awk '{print $2}' "$ARTIFACT_MANIFEST")
fi
if [[ -d /opt/printproxy ]]; then
    find /opt/printproxy -xdev -depth -type d -empty -delete
    [[ ! -d /opt/printproxy ]] || echo 'Preserved untracked files under /opt/printproxy.' >&2
fi
if [[ -d /etc/systemd/system/printproxy.service.d ]]; then
    rmdir --ignore-fail-on-non-empty /etc/systemd/system/printproxy.service.d || true
fi
systemctl daemon-reload

DATA_DIR=$(conf_get DATA_DIR "$CONFIG_FILE")
SPOOL_DIR=$(conf_get SPOOL_DIR "$CONFIG_FILE")
LOG_DIR=$(conf_get LOG_DIR "$CONFIG_FILE")

if [[ $PURGE_DATA == yes ]]; then
    for target in "$DATA_DIR" "$SPOOL_DIR" "$LOG_DIR"; do
        case "$target" in
            /var/lib/printproxy/jobs|/var/lib/printproxy/spool|/var/log/printproxy)
                if [[ -d $target && ! -L $target ]]; then
                    find "$target" -xdev -depth -delete
                fi
                ;;
            '') ;;
            *) echo "Preserved non-default custom data path for safety: $target" >&2 ;;
        esac
    done
    echo 'Default printproxy data directories were deleted and cannot be recovered except from backups.'
else
    echo "Archives and spool preserved: ${DATA_DIR:-unknown}, ${SPOOL_DIR:-unknown}"
fi

if [[ $PURGE_CONFIG == yes ]]; then
    if [[ -d $CONFIG_DIR && ! -L $CONFIG_DIR ]]; then
        find "$CONFIG_DIR" -xdev -depth -delete
    fi
    echo "Configuration and key removed from /etc, but a root-only recovery copy remains at $recovery_backup"
else
    echo "Configuration and HMAC key preserved in $CONFIG_DIR"
fi

echo "Uninstall complete. Direct printing target: ${PRINTER_IP:-10.1.2.200}:${PRINTER_PORT:-9100}."
