#!/bin/bash
set -Eeuo pipefail
umask 077

PROJECT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
CONFIG_DIR=/etc/printproxy
CONFIG_FILE=$CONFIG_DIR/printproxy.conf
INSTALL_STATE=$CONFIG_DIR/install-state
ARTIFACT_MANIFEST=$CONFIG_DIR/artifacts.sha256
OPT_DIR=/opt/printproxy
BACKUP_ROOT=/var/backups/printproxy
LOCK_FILE=/run/lock/printproxy-install.lock

log() { printf '[printproxy-install] %s\n' "$*"; }
warn() { printf '[printproxy-install] WARNING: %s\n' "$*" >&2; }
die() { printf '[printproxy-install] ERROR: %s\n' "$*" >&2; exit 1; }

on_error() {
    code=$?
    warn "installation stopped at line ${BASH_LINENO[0]} (exit $code). Existing network addresses, routes and gateway were not rewritten."
    exit "$code"
}
trap on_error ERR

[[ ${EUID:-$(id -u)} -eq 0 ]] || die 'run as root: sudo ./install.sh'
exec 9>"$LOCK_FILE"
flock -n 9 || die 'another printproxy install/uninstall is running'

[[ -r /etc/os-release ]] || die 'cannot identify operating system'
# shellcheck disable=SC1091
. /etc/os-release
[[ ${ID:-} == debian ]] || die "this installer supports Debian; detected ${ID:-unknown}"
case "${VERSION_ID:-}" in
    12|13) log "Detected Debian ${VERSION_ID}" ;;
    *) warn "Debian ${VERSION_ID:-unknown} is not in the tested 12/13 set; feature checks will still run" ;;
esac
[[ -d /run/systemd/system ]] || die 'systemd is required'

declare -a packages=(python3 iproute2 util-linux iputils-arping logrotate)
declare -a missing=()
for package in "${packages[@]}"; do
    dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q 'install ok installed' || missing+=("$package")
done
if ((${#missing[@]})); then
    log "Installing missing packages only: ${missing[*]}"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install --no-install-recommends -y "${missing[@]}"
fi

python3 - <<'PY' || die 'Python 3.11 or newer is required'
import sys
assert sys.version_info >= (3, 11), sys.version
PY

[[ -f "$PROJECT_DIR/printproxy.py" && -f "$PROJECT_DIR/printproxy_core.py" ]] || die 'run install.sh from the complete project directory'

if ! getent group printproxy >/dev/null 2>&1; then
    groupadd --system printproxy
fi
install -d -m 0750 -o root -g printproxy "$CONFIG_DIR"
if [[ ! -e "$CONFIG_FILE" ]]; then
    install -m 0640 -o root -g root "$PROJECT_DIR/config/printproxy.conf" "$CONFIG_FILE"
else
    if ! cmp -s "$PROJECT_DIR/config/printproxy.conf" "$CONFIG_FILE"; then
        install -m 0640 -o root -g root "$PROJECT_DIR/config/printproxy.conf" "$CONFIG_FILE.dist"
        warn "Preserved existing $CONFIG_FILE; new defaults are in $CONFIG_FILE.dist"
    fi
fi

python3 -I "$PROJECT_DIR/printproxy.py" --config "$CONFIG_FILE" --check-config >/dev/null || die 'configuration validation failed'

conf_get() {
    local key=$1 file=${2:-$CONFIG_FILE}
    awk -v wanted="$key" '
        /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
        {
            p=index($0,"="); if (!p) next
            k=substr($0,1,p-1); gsub(/^[[:space:]]+|[[:space:]]+$/,"",k)
            if (k==wanted) {
                v=substr($0,p+1); gsub(/^[[:space:]]+|[[:space:]]+$/,"",v)
                gsub(/^['\''\"]|['\''\"]$/,"",v); print v; exit
            }
        }
    ' "$file"
}

VIP=$(conf_get LISTEN_IP)
PREFIX=$(conf_get VIRTUAL_PREFIX)
PRINTER_IP=$(conf_get PRINTER_IP)
PRINTER_PORT=$(conf_get PRINTER_PORT)
LISTEN_PORT=$(conf_get LISTEN_PORT)
CONFIG_IFACE=$(conf_get NETWORK_INTERFACE)
DATA_DIR=$(conf_get DATA_DIR)
SPOOL_DIR=$(conf_get SPOOL_DIR)
LOG_DIR=$(conf_get LOG_DIR)
HMAC_KEY_FILE=$(conf_get HMAC_KEY_FILE)
ENABLE_FIREWALL=$(conf_get ENABLE_FIREWALL)
PROTOCOL=$(conf_get PROXY_PROTOCOL)

[[ $PROTOCOL == raw ]] || die 'only PROXY_PROTOCOL=raw is supported safely'
[[ $HMAC_KEY_FILE == /etc/printproxy/integrity.key ]] || die 'installer requires HMAC_KEY_FILE=/etc/printproxy/integrity.key'
for path in "$DATA_DIR" "$SPOOL_DIR" "$LOG_DIR"; do
    [[ $path =~ ^/[A-Za-z0-9._/-]+$ && $path != / ]] || die "unsafe service path: $path"
done
python3 - "$DATA_DIR" "$SPOOL_DIR" "$LOG_DIR" <<'PY' || die 'service paths must stay in dedicated printproxy trees and may not be symlinks'
import os, pathlib, sys
data, spool, log = map(pathlib.Path, sys.argv[1:])
def inside(path, base, allow_base=False):
    absolute=path.absolute()
    base=pathlib.Path(base).resolve()
    for component in (absolute, *absolute.parents):
        if component.exists() and component.is_symlink():
            raise SystemExit(f"symlink path component forbidden: {component}")
        if component == component.parent:
            break
    absolute=absolute.resolve(strict=False)
    if (absolute == base and not allow_base) or base not in absolute.parents and absolute != base:
        raise SystemExit(f"unsafe path {absolute}; expected below {base}")
inside(data, "/var/lib/printproxy")
inside(spool, "/var/lib/printproxy")
inside(log, "/var/log/printproxy", allow_base=True)
paths=(data.resolve(strict=False), spool.resolve(strict=False), log.resolve(strict=False))
for index, left in enumerate(paths):
    for right in paths[index+1:]:
        if left == right or left in right.parents or right in left.parents:
            raise SystemExit(f"service paths overlap: {left} / {right}")
PY

if [[ $CONFIG_IFACE == auto ]]; then
    IFACE=$(ip -o route get "$PRINTER_IP" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
    [[ -n $IFACE ]] || die "cannot determine interface used to reach $PRINTER_IP"
else
    IFACE=$CONFIG_IFACE
fi
[[ $IFACE =~ ^[A-Za-z0-9_.:@-]{1,64}$ ]] || die 'detected unsafe interface name'
ip link show dev "$IFACE" >/dev/null 2>&1 || die "interface $IFACE does not exist"
[[ $IFACE != lo ]] || die 'refusing to place the LAN service address on loopback'
log "Detected print LAN interface: $IFACE"
IP_ADDR_JSON=$(ip -j -4 addr show dev "$IFACE")
python3 - "$VIP" "$PRINTER_IP" "$IP_ADDR_JSON" <<'PY' || die 'VIP and printer must share one directly connected IPv4 prefix on the selected interface'
import ipaddress, json, sys
vip=ipaddress.ip_address(sys.argv[1]); printer=ipaddress.ip_address(sys.argv[2])
data=json.loads(sys.argv[3])
matches=[]
for link in data:
    for item in link.get("addr_info", []):
        if item.get("family") != "inet" or item.get("scope") != "global": continue
        network=ipaddress.ip_network(f"{item['local']}/{item['prefixlen']}", strict=False)
        if vip in network and printer in network and vip not in {network.network_address, network.broadcast_address}:
            matches.append(str(network))
if len(set(matches)) != 1:
    raise SystemExit(f"connected-prefix matches: {matches}")
print(f"Connected print LAN: {matches[0]}")
PY

declare -a managers=()
if command -v nmcli >/dev/null 2>&1; then
    nm_state=$(nmcli -g GENERAL.STATE device show "$IFACE" 2>/dev/null || true)
    [[ $nm_state == *connected* || $nm_state == 100* ]] && managers+=(NetworkManager)
fi
if command -v networkctl >/dev/null 2>&1; then
    networkd_state=$(networkctl show "$IFACE" -p SetupState --value 2>/dev/null || true)
    [[ $networkd_state == configured || $networkd_state == configuring ]] && managers+=(systemd-networkd)
fi
if [[ -r /run/network/ifstate ]] && grep -qE "^${IFACE}=" /run/network/ifstate; then
    managers+=(ifupdown)
fi
if ((${#managers[@]} == 0)); then
    NETWORK_BACKEND=unidentified
    warn "No network manager claimed $IFACE; the additive systemd VIP unit will be used"
else
    NETWORK_BACKEND=$(IFS=,; printf '%s' "${managers[*]}")
    log "Detected networking backend(s): $NETWORK_BACKEND"
fi
if ((${#managers[@]} > 1)); then
    warn "Multiple managers appear active for $IFACE; no manager configuration will be edited"
fi
log 'Persistence uses a dedicated additive oneshot unit; no NetworkManager profile, .network file, or /etc/network/interfaces stanza is rewritten.'

EXISTING_IFACE=$(ip -o -4 addr show | awk -v ip="$VIP" '$4 ~ ("^" ip "/") {print $2; exit}')
OLD_OWNED=
if [[ -r $INSTALL_STATE ]]; then
    OLD_OWNED=$(conf_get VIP_OWNED "$INSTALL_STATE" || true)
    OLD_VIP=$(conf_get VIP "$INSTALL_STATE" || true)
    [[ -z $OLD_VIP || $OLD_VIP == "$VIP" ]] || die "installed VIP is $OLD_VIP but configuration now requests $VIP; uninstall before changing service identity"
    OLD_PREFIX=$(conf_get PREFIX "$INSTALL_STATE" || true)
    OLD_IFACE=$(conf_get INTERFACE "$INSTALL_STATE" || true)
    [[ -z $OLD_PREFIX || $OLD_PREFIX == "$PREFIX" ]] || die "installed prefix is /$OLD_PREFIX; explicit uninstall/migration is required"
    [[ -z $OLD_IFACE || $OLD_IFACE == "$IFACE" ]] || die "installed interface is $OLD_IFACE; explicit uninstall/migration is required"
fi
if [[ -n $EXISTING_IFACE ]]; then
    [[ $EXISTING_IFACE == "$IFACE" ]] || die "$VIP already exists on $EXISTING_IFACE, not $IFACE"
    if [[ $OLD_OWNED == yes ]]; then
        VIP_OWNED=yes
        log "$VIP is already present and owned by the prior printproxy installation"
    else
        VIP_OWNED=no
        warn "$VIP pre-existed this installation; uninstall will not remove it"
    fi
else
    if arping -D -q -I "$IFACE" -c 3 -w 3 "$VIP"; then
        VIP_OWNED=yes
    else
        die "duplicate-address detection reports $VIP already in use"
    fi
fi

if ss -H -ltn "sport = :$LISTEN_PORT" | grep -q .; then
    if systemctl is-active --quiet printproxy.service 2>/dev/null; then
        log "Listener port $LISTEN_PORT belongs to the active printproxy service (idempotent reinstall)"
    else
        die "TCP port $LISTEN_PORT is already listening; inspect with: ss -lntp"
    fi
fi

log "Non-aggressive printer service probe (TCP connect only):"
PROBE_RESULT=$(python3 - "$PRINTER_IP" <<'PY'
import socket, sys
host=sys.argv[1]
opened=[]
for port, name in ((9100,"RAW/JetDirect"),(515,"LPR"),(631,"IPP")):
    try:
        with socket.create_connection((host,port),timeout=1.5):
            print(f"  {port}/tcp {name}: open")
            opened.append(str(port))
    except OSError as exc:
        print(f"  {port}/tcp {name}: closed/unreachable ({exc.__class__.__name__})")
print("OPEN=" + ",".join(opened))
PY
)
printf '%s\n' "$PROBE_RESULT" | grep -v '^OPEN='
OPEN_PORTS=$(printf '%s\n' "$PROBE_RESULT" | awk -F= '/^OPEN=/{print $2}')
if [[ ,$OPEN_PORTS, != *,9100,* ]]; then
    if [[ ,$OPEN_PORTS, == *,515,* || ,$OPEN_PORTS, == *,631,* ]]; then
        die 'printer exposes LPR/IPP but not RAW 9100. This RAW proxy must not be placed blindly in front of an interactive protocol; see docs/ARCHITECTURE.md.'
    fi
    warn "Printer is currently unreachable on all three tested ports; installation continues for offline recovery, using configured port $PRINTER_PORT"
fi
if [[ $PRINTER_PORT != 9100 ]]; then
    die 'PROXY_PROTOCOL=raw currently requires PRINTER_PORT=9100 after service discovery'
fi

if id printproxy >/dev/null 2>&1; then
    uid=$(id -u printproxy)
    [[ $uid -gt 0 && $uid -lt 1000 ]] || die 'existing printproxy account is not a non-root system user'
    id -nG printproxy | tr ' ' '\n' | grep -qx printproxy || die 'existing printproxy user is not a member of the dedicated group'
    [[ $(id -gn printproxy) == printproxy ]] || die 'existing printproxy account must use printproxy as its primary group'
    shell=$(getent passwd printproxy | cut -d: -f7)
    [[ $shell == /usr/sbin/nologin || $shell == /bin/false ]] || die 'existing printproxy account has an interactive shell'
else
    useradd --system --gid printproxy --home-dir /var/lib/printproxy --shell /usr/sbin/nologin printproxy
fi
PRINTPROXY_GROUP=printproxy

if [[ ! -r $INSTALL_STATE ]]; then
    for collision in \
        /etc/systemd/system/printproxy.service \
        /etc/systemd/system/printproxy-vip.service \
        /etc/systemd/system/printproxy-firewall.service \
        /usr/local/libexec/printproxy-vip \
        /usr/local/libexec/printproxy-firewall \
        /usr/local/sbin/printproxyctl; do
        [[ ! -e $collision && ! -L $collision ]] || die "pre-existing unowned artifact: $collision"
    done
    if [[ -d $OPT_DIR ]] && find "$OPT_DIR" -mindepth 1 -print -quit | grep -q .; then
        die "$OPT_DIR is non-empty but no printproxy installer state exists"
    fi
    for target in "$DATA_DIR" "$SPOOL_DIR" "$LOG_DIR"; do
        if [[ -e $target ]]; then
            [[ ! -L $target && -d $target ]] || die "unsafe pre-existing path: $target"
            owner=$(stat -c '%U' "$target")
            [[ $owner == printproxy ]] || die "pre-existing $target is owned by $owner, not printproxy"
        fi
    done
fi

install -d -m 0750 -o printproxy -g "$PRINTPROXY_GROUP" "$DATA_DIR" "$SPOOL_DIR" "$LOG_DIR"
install -d -m 0750 -o printproxy -g "$PRINTPROXY_GROUP" \
    "$SPOOL_DIR/states" "$SPOOL_DIR/receiving" "$SPOOL_DIR/requests" "$SPOOL_DIR/locks"

require_supported_storage() {
    local path=$1 purpose=$2 filesystem source
    filesystem=$(findmnt --noheadings --output FSTYPE --target "$path" | awk 'NF { print $1; exit }')
    source=$(findmnt --noheadings --output SOURCE --target "$path" | awk 'NF { print $1; exit }')
    [[ -n $filesystem && -n $source ]] || die "cannot identify the filesystem backing $purpose ($path)"
    case "$filesystem" in
        ext3|ext4|xfs|btrfs|zfs) ;;
        *)
            die "$purpose ($path) is on unsupported filesystem '$filesystem'. Use local ext3/ext4, XFS, Btrfs or ZFS; network, FUSE/DrvFS, overlay and volatile filesystems are not suitable for the durable audit store."
            ;;
    esac
    log "$purpose storage: $source ($filesystem)"
}

require_supported_storage "$DATA_DIR" DATA_DIR
require_supported_storage "$SPOOL_DIR" SPOOL_DIR
install -d -m 0755 -o root -g root "$OPT_DIR" /usr/local/libexec

install -d -m 0700 -o root -g root "$BACKUP_ROOT"
BACKUP_DIR=$(mktemp -d "$BACKUP_ROOT/$(date -u +%Y%m%dT%H%M%SZ).XXXXXX")
chmod 0700 "$BACKUP_DIR"
chown root:root "$BACKUP_DIR"
backup_if_present() {
    local target=$1
    if [[ -e $target || -L $target ]]; then
        cp -a -- "$target" "$BACKUP_DIR/$(basename -- "$target")"
    fi
}
for target in \
    "$OPT_DIR/printproxy.py" "$OPT_DIR/printproxy_core.py" "$OPT_DIR/printproxyctl.py" \
    /etc/systemd/system/printproxy.service /etc/systemd/system/printproxy-vip.service \
    /etc/systemd/system/printproxy-firewall.service /etc/logrotate.d/printproxy \
    /etc/systemd/system/printproxy-vip-watch.service /etc/systemd/system/printproxy-vip-watch.timer \
    /usr/local/libexec/printproxy-vip /usr/local/libexec/printproxy-firewall \
    /usr/local/sbin/printproxyctl "$CONFIG_FILE" "$INSTALL_STATE" "$ARTIFACT_MANIFEST" \
    "$HMAC_KEY_FILE" /etc/systemd/system/printproxy.service.d/paths.conf; do
    backup_if_present "$target"
done
find "$BACKUP_DIR" -type f ! -name MANIFEST.sha256 -print0 | sort -z | \
    xargs -0 -r sha256sum -- >"$BACKUP_DIR/MANIFEST.sha256"

install -m 0755 -o root -g root "$PROJECT_DIR/printproxy.py" "$OPT_DIR/printproxy.py"
install -m 0644 -o root -g root "$PROJECT_DIR/printproxy_core.py" "$OPT_DIR/printproxy_core.py"
install -m 0755 -o root -g root "$PROJECT_DIR/printproxyctl.py" "$OPT_DIR/printproxyctl.py"
[[ -f $PROJECT_DIR/README.md ]] && install -m 0644 -o root -g root "$PROJECT_DIR/README.md" "$OPT_DIR/README.md"
install -d -m 0755 -o root -g root "$OPT_DIR/docs"
if compgen -G "$PROJECT_DIR/docs/*.md" >/dev/null; then
    for document in "$PROJECT_DIR"/docs/*.md; do
        install -m 0644 -o root -g root "$document" "$OPT_DIR/docs/$(basename "$document")"
    done
fi

install -m 0755 -o root -g root "$PROJECT_DIR/network/printproxy-vip" /usr/local/libexec/printproxy-vip
install -m 0755 -o root -g root "$PROJECT_DIR/network/printproxy-firewall" /usr/local/libexec/printproxy-firewall
install -m 0644 -o root -g root "$PROJECT_DIR/systemd/printproxy.service" /etc/systemd/system/printproxy.service
install -m 0644 -o root -g root "$PROJECT_DIR/systemd/printproxy-vip.service" /etc/systemd/system/printproxy-vip.service
install -m 0644 -o root -g root "$PROJECT_DIR/systemd/printproxy-firewall.service" /etc/systemd/system/printproxy-firewall.service
install -m 0644 -o root -g root "$PROJECT_DIR/systemd/printproxy-vip-watch.service" /etc/systemd/system/printproxy-vip-watch.service
install -m 0644 -o root -g root "$PROJECT_DIR/systemd/printproxy-vip-watch.timer" /etc/systemd/system/printproxy-vip-watch.timer
logrotate_tmp=$(mktemp /etc/logrotate.d/.printproxy.XXXXXX)
{
    printf '%s/printproxy.log {\n' "$LOG_DIR"
    tail -n +2 "$PROJECT_DIR/logrotate/printproxy"
} >"$logrotate_tmp"
install -m 0644 -o root -g root "$logrotate_tmp" /etc/logrotate.d/printproxy
rm -f -- "$logrotate_tmp"
if [[ -e /usr/local/sbin/printproxyctl && ! -L /usr/local/sbin/printproxyctl ]]; then
    die '/usr/local/sbin/printproxyctl is not the owned symlink expected by printproxy'
fi
ln -sfnT /opt/printproxy/printproxyctl.py /usr/local/sbin/printproxyctl

chown root:"$PRINTPROXY_GROUP" "$CONFIG_FILE"
chmod 0640 "$CONFIG_FILE"
if [[ ! -e $HMAC_KEY_FILE ]]; then
    key_tmp=$(mktemp "$CONFIG_DIR/.integrity.key.XXXXXX")
    python3 - "$key_tmp" <<'PY'
import os, secrets, sys
fd=os.open(sys.argv[1], os.O_WRONLY | os.O_TRUNC)
try:
    os.write(fd, secrets.token_hex(32).encode("ascii"))
    os.fsync(fd)
finally:
    os.close(fd)
PY
    install -m 0600 -o root -g root "$key_tmp" "$HMAC_KEY_FILE"
    rm -f -- "$key_tmp"
    sync -f "$HMAC_KEY_FILE"
    sync -f "$CONFIG_DIR"
    log "Generated HMAC key at $HMAC_KEY_FILE (root:root 0600)"
else
    [[ -f $HMAC_KEY_FILE && ! -L $HMAC_KEY_FILE ]] || die 'existing integrity key must be a regular non-symlink file'
    chown root:root "$HMAC_KEY_FILE"
    chmod 0600 "$HMAC_KEY_FILE"
    log 'Preserved the existing integrity key'
fi

FIREWALL_OWNED=no
old_fw_owned=
[[ -r $INSTALL_STATE ]] && old_fw_owned=$(conf_get FIREWALL_OWNED "$INSTALL_STATE" || true)
if [[ $ENABLE_FIREWALL == yes ]]; then
    if systemctl is-active --quiet firewalld.service 2>/dev/null || \
       { command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^Status: active'; }; then
        die 'ENABLE_FIREWALL=yes requires native nftables ownership; firewalld/UFW is active. Use the application ACL or integrate with that manager explicitly.'
    fi
    if ! command -v nft >/dev/null 2>&1; then
        apt-get install --no-install-recommends -y nftables
    fi
    if nft list table inet printproxy_filter >/dev/null 2>&1 && [[ $old_fw_owned != yes ]]; then
        die 'nftables table inet printproxy_filter already exists but is not owned by this installer'
    fi
    FIREWALL_OWNED=yes
elif [[ $old_fw_owned == yes ]] && [[ -x /usr/local/libexec/printproxy-firewall ]]; then
    /usr/local/libexec/printproxy-firewall down
fi

state_tmp=$(mktemp "$CONFIG_DIR/.install-state.XXXXXX")
{
    printf 'SCHEMA_VERSION=1\n'
    printf 'INSTALLED_AT=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)"
    printf 'INTERFACE=%s\n' "$IFACE"
    printf 'NETWORK_BACKEND=%s\n' "$NETWORK_BACKEND"
    printf 'VIP=%s\n' "$VIP"
    printf 'PREFIX=%s\n' "$PREFIX"
    printf 'VIP_OWNED=%s\n' "$VIP_OWNED"
    printf 'FIREWALL_OWNED=%s\n' "$FIREWALL_OWNED"
    printf 'BACKUP_DIR=%s\n' "$BACKUP_DIR"
} >"$state_tmp"
chmod 0600 "$state_tmp"
chown root:root "$state_tmp"
mv -f -- "$state_tmp" "$INSTALL_STATE"
sync -f "$CONFIG_DIR"

install -d -m 0755 -o root -g root /etc/systemd/system/printproxy.service.d
paths_tmp=$(mktemp /etc/systemd/system/printproxy.service.d/.paths.XXXXXX)
{
    printf '[Service]\n'
    printf 'ReadWritePaths=\n'
    printf 'ReadWritePaths=%s %s %s\n' "$DATA_DIR" "$SPOOL_DIR" "$LOG_DIR"
} >"$paths_tmp"
chmod 0644 "$paths_tmp"
mv -f -- "$paths_tmp" /etc/systemd/system/printproxy.service.d/paths.conf

artifact_tmp=$(mktemp "$CONFIG_DIR/.artifacts.sha256.XXXXXX")
{
    find "$OPT_DIR" -xdev -type f -print0 | sort -z | xargs -0 -r sha256sum --
    sha256sum -- \
        /etc/systemd/system/printproxy.service \
        /etc/systemd/system/printproxy-vip.service \
        /etc/systemd/system/printproxy-firewall.service \
        /etc/systemd/system/printproxy-vip-watch.service \
        /etc/systemd/system/printproxy-vip-watch.timer \
        /etc/systemd/system/printproxy.service.d/paths.conf \
        /etc/logrotate.d/printproxy \
        /usr/local/libexec/printproxy-vip \
        /usr/local/libexec/printproxy-firewall
} >"$artifact_tmp"
chmod 0600 "$artifact_tmp"
chown root:root "$artifact_tmp"
mv -f -- "$artifact_tmp" "$ARTIFACT_MANIFEST"
sync -f "$ARTIFACT_MANIFEST"
sync -f "$CONFIG_DIR"
sync -f "$OPT_DIR"
sync -f /etc/systemd/system
sync -f /usr/local/libexec

systemd-analyze verify /etc/systemd/system/printproxy.service /etc/systemd/system/printproxy-vip.service /etc/systemd/system/printproxy-firewall.service /etc/systemd/system/printproxy-vip-watch.service /etc/systemd/system/printproxy-vip-watch.timer
if ! LOGROTATE_CHECK_OUTPUT=$(logrotate --debug /etc/logrotate.d/printproxy 2>&1); then
    printf '%s\n' "$LOGROTATE_CHECK_OUTPUT" >&2
    die 'logrotate configuration validation failed'
fi
systemctl daemon-reload
systemctl enable printproxy-vip.service printproxy-firewall.service printproxy-vip-watch.timer printproxy.service >/dev/null
/usr/local/libexec/printproxy-vip up
systemctl start printproxy-vip.service
systemctl restart printproxy-firewall.service
systemctl restart printproxy.service
systemctl start printproxy-vip-watch.timer

if timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -qx yes; then
    log 'Clock synchronization: OK'
else
    warn 'Clock is not reported synchronized. UTC timestamps remain local audit timestamps, not certified timestamps.'
fi

listener_ready=no
for ((listener_attempt = 1; listener_attempt <= 40; listener_attempt++)); do
    if systemctl is-active --quiet printproxy.service && \
       ss -H -ltn4 "sport = :$LISTEN_PORT" | \
           awk -v endpoint="$VIP:$LISTEN_PORT" '$4 == endpoint { found=1 } END { exit !found }'; then
        listener_ready=yes
        break
    fi
    sleep 0.25
done
if [[ $listener_ready != yes ]]; then
    systemctl --no-pager --full status printproxy.service >&2 || true
    ss -H -ltn4 "sport = :$LISTEN_PORT" >&2 || true
    journalctl -u printproxy.service -n 30 --no-pager >&2 || true
    die 'configured listener socket did not become active within 10 seconds'
fi
/usr/local/sbin/printproxyctl status || die 'post-install service/head health check failed'
systemctl --no-pager --full status printproxy.service
log "Installed successfully. Listener: $VIP:$LISTEN_PORT -> printer $PRINTER_IP:$PRINTER_PORT"
log 'Change the management software destination only after printproxyctl self-test succeeds.'
log "Rollback is immediate: restore the management software destination to $PRINTER_IP:$PRINTER_PORT."
