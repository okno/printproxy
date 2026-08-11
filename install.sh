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
MANAGE_VIPS=no
NETWORK_APPLIED=no
MUTATION_STARTED=no
INSTALL_COMMITTED=no
HAD_INSTALL_STATE=no
[[ -f $INSTALL_STATE && ! -L $INSTALL_STATE ]] && HAD_INSTALL_STATE=yes
declare -a VIPS_APPLIED=()

usage() {
    cat <<'EOF'
Usage: sudo ./install.sh [--manage-vips]

By default the installer validates existing LISTEN_IP addresses but does not
claim missing addresses. --manage-vips explicitly authorizes duplicate-address
detection plus additive creation/persistence of the configured virtual IPs.
No primary address, route, gateway or network-manager profile is rewritten.
EOF
}

for argument in "$@"; do
    case "$argument" in
        --manage-vips) MANAGE_VIPS=yes ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'Unknown option: %s\n' "$argument" >&2; usage >&2; exit 2 ;;
    esac
done

log() { printf '[printproxy-install] %s\n' "$*"; }
warn() { printf '[printproxy-install] WARNING: %s\n' "$*" >&2; }
die() { printf '[printproxy-install] ERROR: %s\n' "$*" >&2; exit 1; }

on_error() {
    code=$?
    trap - ERR
    if [[ ${INSTALL_COMMITTED:-no} != yes && ${MUTATION_STARTED:-no} == yes ]]; then
        systemctl stop printproxy-vip-watch.timer printproxy-vip-watch.service \
            printproxy.service printproxy-firewall.service printproxy-vip.service \
            >/dev/null 2>&1 || true
        if [[ ${NETWORK_APPLIED:-no} == yes && -n ${IFACE:-} && -n ${PREFIX:-} ]]; then
            for rollback_vip in "${VIPS_APPLIED[@]-}"; do
                [[ -n $rollback_vip ]] || continue
                ip address del "$rollback_vip/$PREFIX" dev "$IFACE" 2>/dev/null || \
                    warn "could not roll back newly applied VIP $rollback_vip/$PREFIX on $IFACE"
            done
        fi
        if [[ -n ${BACKUP_DIR:-} && -f $BACKUP_DIR/install-state ]]; then
            install -m 0600 -o root -g root "$BACKUP_DIR/install-state" "$INSTALL_STATE" || \
                warn 'could not restore the previous installer state'
        elif [[ ${HAD_INSTALL_STATE:-no} == no ]]; then
            rm -f -- "$INSTALL_STATE" || true
            systemctl disable printproxy.service printproxy-firewall.service \
                printproxy-vip.service printproxy-vip-watch.timer >/dev/null 2>&1 || true
        fi
        sync -f "$CONFIG_DIR" 2>/dev/null || true
        warn 'installation rollback left printproxy stopped; inspect the recovery backup before restarting'
    elif [[ ${SERVICE_WAS_ACTIVE:-no} == yes ]]; then
        warn 'printproxy.service was stopped for the security preflight and remains stopped'
    fi
    warn "installation stopped at line ${BASH_LINENO[0]} (exit $code). No primary address, route or gateway was rewritten."
    [[ -z ${BACKUP_DIR:-} ]] || warn "Root-only recovery backup: $BACKUP_DIR"
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

declare -a packages=(
    python3 python3-reportlab tesseract-ocr tesseract-ocr-ita
    iproute2 util-linux iputils-arping logrotate
)
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

python3 - <<'PY' || die 'Python 3.11+ with ReportLab is required'
import sys
assert sys.version_info >= (3, 11), sys.version
import reportlab
PY
command -v tesseract >/dev/null 2>&1 || die 'tesseract OCR executable is required'
tesseract --list-langs 2>/dev/null | grep -qx ita || die 'Italian Tesseract language data is required (tesseract-ocr-ita)'

[[ -f "$PROJECT_DIR/printproxy.py" && -f "$PROJECT_DIR/printproxy_core.py" && \
   -f "$PROJECT_DIR/receipt_renderer.py" ]] || die 'run install.sh from the complete project directory'
if [[ -e $INSTALL_STATE || -L $INSTALL_STATE ]]; then
    [[ -f $INSTALL_STATE && ! -L $INSTALL_STATE ]] || die "unsafe installer state: $INSTALL_STATE"
fi

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

VIP_CSV=$(conf_get LISTEN_IP)
PREFIX=$(conf_get VIRTUAL_PREFIX)
PRINTER_IP_CSV=$(conf_get PRINTER_IP)
PRINTER_PORT_CSV=$(conf_get PRINTER_PORT)
LISTEN_PORT_CSV=$(conf_get LISTEN_PORT)
CONFIG_IFACE=$(conf_get NETWORK_INTERFACE)
DATA_DIR=$(conf_get DATA_DIR)
SPOOL_DIR=$(conf_get SPOOL_DIR)
LOG_DIR=$(conf_get LOG_DIR)
HMAC_KEY_FILE=$(conf_get HMAC_KEY_FILE)
ENABLE_FIREWALL=$(conf_get ENABLE_FIREWALL)
PROTOCOL=$(conf_get PROXY_PROTOCOL)
DELIVERY_MODE=$(conf_get DELIVERY_MODE)

split_csv() {
    local value=$1 key=$2 output_name=$3 item
    local -a raw_items=()
    local -n output=$output_name
    IFS=',' read -r -a raw_items <<<"$value"
    output=()
    for item in "${raw_items[@]}"; do
        item=${item#"${item%%[![:space:]]*}"}
        item=${item%"${item##*[![:space:]]}"}
        [[ -n $item ]] || die "$key contains an empty CSV entry"
        output+=("$item")
    done
}

declare -a VIPS LISTEN_PORTS PRINTER_IPS PRINTER_PORTS
split_csv "$VIP_CSV" LISTEN_IP VIPS
split_csv "$LISTEN_PORT_CSV" LISTEN_PORT LISTEN_PORTS
split_csv "$PRINTER_IP_CSV" PRINTER_IP PRINTER_IPS
split_csv "$PRINTER_PORT_CSV" PRINTER_PORT PRINTER_PORTS
# Persist and compare canonical positional lists, not administrator whitespace.
VIP_CSV=$(IFS=,; printf '%s' "${VIPS[*]}")
LISTEN_PORT_CSV=$(IFS=,; printf '%s' "${LISTEN_PORTS[*]}")
PRINTER_IP_CSV=$(IFS=,; printf '%s' "${PRINTER_IPS[*]}")
PRINTER_PORT_CSV=$(IFS=,; printf '%s' "${PRINTER_PORTS[*]}")
PROXY_COUNT=${#VIPS[@]}
((PROXY_COUNT > 0)) || die 'at least one proxy mapping is required'
if ((${#LISTEN_PORTS[@]} != PROXY_COUNT || ${#PRINTER_IPS[@]} != PROXY_COUNT || ${#PRINTER_PORTS[@]} != PROXY_COUNT)); then
    die "proxy CSV length mismatch after validation: LISTEN_IP=$PROXY_COUNT LISTEN_PORT=${#LISTEN_PORTS[@]} PRINTER_IP=${#PRINTER_IPS[@]} PRINTER_PORT=${#PRINTER_PORTS[@]}"
fi

[[ $PROTOCOL == raw ]] || die 'only PROXY_PROTOCOL=raw is supported safely'
if [[ -z $DELIVERY_MODE ]]; then
    die 'existing config predates bidirectional delivery. Add DELIVERY_MODE=transparent_duplex (recommended after queue review) or DELIVERY_MODE=store_forward explicitly; compare /etc/printproxy/printproxy.conf.dist'
fi
case "$DELIVERY_MODE" in
    transparent_duplex) ;;
    store_forward)
        warn 'DELIVERY_MODE=store_forward is explicitly selected: printer responses are not relayed to the client.'
        ;;
    *) die 'DELIVERY_MODE must be transparent_duplex or store_forward' ;;
esac
[[ $HMAC_KEY_FILE == /etc/printproxy/integrity.key ]] || die 'installer requires HMAC_KEY_FILE=/etc/printproxy/integrity.key'
for path in "$DATA_DIR" "$SPOOL_DIR" "$LOG_DIR"; do
    [[ $path =~ ^/[A-Za-z0-9._/-]+$ && $path != / ]] || die "unsafe service path: $path"
done

# Quiesce the only process authorized to write the service-owned trees before
# inspecting or mutating them. This closes the daemon-vs-installer rename race.
SERVICE_WAS_ACTIVE=no
if systemctl is-active --quiet printproxy.service 2>/dev/null; then
    SERVICE_WAS_ACTIVE=yes
    log 'Stopping printproxy.service for filesystem and lifecycle validation'
    systemctl stop printproxy.service
fi
systemctl is-active --quiet printproxy.service 2>/dev/null && \
    die 'printproxy.service did not stop; refusing filesystem validation'

canonical_path() {
    python3 -c 'import os, sys; print(os.path.abspath(sys.argv[1]))' "$1"
}
DATA_DIR=$(canonical_path "$DATA_DIR")
SPOOL_DIR=$(canonical_path "$SPOOL_DIR")
LOG_DIR=$(canonical_path "$LOG_DIR")
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

# A mapping-aware installer state is authoritative: an installed tuple may be
# reordered and new tuples may be added, but removing/rebinding one requires an
# explicit uninstall/migration.  Pre-schema-3 state did not persist enough
# fields, so infer only from bounded operational JSON with the daemon stopped.
if [[ -r $INSTALL_STATE ]]; then
    old_listen_port_list=$(conf_get LISTEN_PORT_LIST "$INSTALL_STATE" || true)
    old_printer_ip_list=$(conf_get PRINTER_IP_LIST "$INSTALL_STATE" || true)
    old_printer_port_list=$(conf_get PRINTER_PORT_LIST "$INSTALL_STATE" || true)
    if [[ -z $old_listen_port_list && -z $old_printer_ip_list && -z $old_printer_port_list ]] && \
       systemctl is-active --quiet printproxy.service 2>/dev/null; then
        die 'legacy installer state requires a maintenance window: stop printproxy.service, run printproxyctl verify/queue, then rerun so historical endpoints can be inferred safely'
    fi
    python3 -I - "$PROJECT_DIR" "$CONFIG_FILE" "$INSTALL_STATE" \
        /etc/systemd/system/printproxy.service.d/paths.conf <<'PY' || \
        die 'configured route lifecycle validation failed; preserve every installed tuple or perform explicit uninstall/migration'
import pathlib
import sys

project_dir = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(project_dir))
from printproxy_core import (  # noqa: E402
    ConfigError,
    StorageError,
    load_settings,
    read_installed_storage_paths,
    validate_installer_route_lifecycle,
)

try:
    settings = load_settings(sys.argv[2])
    try:
        legacy_storage_paths = read_installed_storage_paths(pathlib.Path(sys.argv[4]))
    except (ConfigError, StorageError, OSError):
        legacy_storage_paths = None
    validate_installer_route_lifecycle(
        settings,
        pathlib.Path(sys.argv[3]),
        legacy_storage_paths=legacy_storage_paths,
    )
except (ConfigError, StorageError, OSError) as exc:
    print(f"printproxy route lifecycle: {exc}", file=sys.stderr)
    raise SystemExit(1) from exc
PY
fi

# A v2 single-route deployment stored operational state directly at SPOOL_DIR.
# Switching to N route-scoped stores while that state is live would silently
# strand a replayable/uncertain job. Require an offline, clean migration first.
if [[ -r $INSTALL_STATE && $PROXY_COUNT -gt 1 ]]; then
    old_vip_csv=$(conf_get VIP_LIST "$INSTALL_STATE" || true)
    [[ -n $old_vip_csv ]] || old_vip_csv=$(conf_get VIP "$INSTALL_STATE" || true)
    old_vip_count=0
    [[ -z $old_vip_csv ]] || old_vip_count=$(awk -F, '{print NF}' <<<"$old_vip_csv")
    if [[ $old_vip_count -eq 1 ]]; then
        if systemctl is-active --quiet printproxy.service 2>/dev/null; then
            die 'single-to-multi migration requires a maintenance window: stop printproxy.service, run printproxyctl verify/queue, then rerun the installer'
        fi
        python3 -I - "$PROJECT_DIR" "$CONFIG_FILE" "$INSTALL_STATE" <<'PY' || \
            die 'legacy flat ledger/archive/spool failed authenticated offline verification; restore single-route mode, inspect printproxyctl verify/queue, and resolve it before enabling multiple proxies'
import pathlib
import sys

project_dir = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(project_dir))
from printproxy_core import (  # noqa: E402
    ConfigError,
    IntegrityError,
    StorageError,
    load_hmac_key,
    load_settings,
    validate_single_to_multi_migration,
)

try:
    settings = load_settings(sys.argv[2])
    key = load_hmac_key(settings, cli=True)
    validate_single_to_multi_migration(settings, pathlib.Path(sys.argv[3]), key)
except (ConfigError, IntegrityError, StorageError, OSError, ValueError) as exc:
    print(f"printproxy single-to-multi integrity preflight: {exc}", file=sys.stderr)
    raise SystemExit(1) from exc
PY
    fi
fi

if [[ $CONFIG_IFACE == auto ]]; then
    IFACE=
    for printer_ip in "${PRINTER_IPS[@]}"; do
        route_iface=$(ip -o route get "$printer_ip" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
        [[ -n $route_iface ]] || die "cannot determine interface used to reach $printer_ip"
        if [[ -z $IFACE ]]; then
            IFACE=$route_iface
        elif [[ $route_iface != "$IFACE" ]]; then
            die "configured printers use different route interfaces ($IFACE and $route_iface); this installer manages one print LAN per service"
        fi
    done
else
    IFACE=$CONFIG_IFACE
fi
[[ $IFACE =~ ^[A-Za-z0-9_.:@-]{1,64}$ ]] || die 'detected unsafe interface name'
ip link show dev "$IFACE" >/dev/null 2>&1 || die "interface $IFACE does not exist"
[[ $IFACE != lo ]] || die 'refusing to place the LAN service address on loopback'
log "Detected print LAN interface: $IFACE"
IP_ADDR_JSON=$(ip -j -4 addr show dev "$IFACE")
python3 - "$VIP_CSV" "$PRINTER_IP_CSV" "$PREFIX" "$IP_ADDR_JSON" <<'PY' || die 'every VIP/printer pair must share the configured directly connected IPv4 prefix on the selected interface'
import ipaddress, json, sys
vips=[ipaddress.ip_address(item.strip()) for item in sys.argv[1].split(",")]
printers=[ipaddress.ip_address(item.strip()) for item in sys.argv[2].split(",")]
configured_prefix=int(sys.argv[3])
if len(vips) != len(printers):
    raise SystemExit("VIP/printer length mismatch")
data=json.loads(sys.argv[4])
networks=[]
for link in data:
    for item in link.get("addr_info", []):
        if item.get("family") == "inet" and item.get("scope") == "global":
            networks.append(ipaddress.ip_network(f"{item['local']}/{item['prefixlen']}", strict=False))
used=set()
for index, (vip, printer) in enumerate(zip(vips, printers), 1):
    matches=[network for network in networks if network.prefixlen == configured_prefix and vip in network and printer in network and vip not in {network.network_address, network.broadcast_address}]
    if len(set(matches)) != 1:
        raise SystemExit(f"proxy-{index:03d} {vip}->{printer}: connected-prefix matches: {matches}")
    used.add(str(matches[0]))
print(f"Connected print LAN(s): {', '.join(sorted(used))}")
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

declare -A OLD_VIP_OWNERSHIP=()
declare -a OLD_VIPS=() OLD_OWNERS=() VIP_OWNERS=()
if [[ -r $INSTALL_STATE ]]; then
    OLD_VIP_CSV=$(conf_get VIP_LIST "$INSTALL_STATE" || true)
    OLD_OWNED_CSV=$(conf_get VIP_OWNED_LIST "$INSTALL_STATE" || true)
    if [[ -z $OLD_VIP_CSV ]]; then
        OLD_VIP_CSV=$(conf_get VIP "$INSTALL_STATE" || true)
        OLD_OWNED_CSV=$(conf_get VIP_OWNED "$INSTALL_STATE" || true)
    fi
    if [[ -n $OLD_VIP_CSV ]]; then
        split_csv "$OLD_VIP_CSV" VIP_LIST OLD_VIPS
        split_csv "$OLD_OWNED_CSV" VIP_OWNED_LIST OLD_OWNERS
        ((${#OLD_VIPS[@]} == ${#OLD_OWNERS[@]})) || die 'installer state has mismatched VIP ownership lists'
        for index in "${!OLD_VIPS[@]}"; do
            case "${OLD_OWNERS[$index]}" in yes|no) ;; *) die 'installer state has unsafe VIP ownership value' ;; esac
            OLD_VIP_OWNERSHIP["${OLD_VIPS[$index]}"]=${OLD_OWNERS[$index]}
        done
        for old_vip in "${OLD_VIPS[@]}"; do
            found=no
            for vip in "${VIPS[@]}"; do
                [[ $vip == "$old_vip" ]] && found=yes
            done
            [[ $found == yes ]] || die "installed VIP $old_vip was removed from configuration; use explicit uninstall/migration so owned addresses are not orphaned"
        done
    fi
    OLD_PREFIX=$(conf_get PREFIX "$INSTALL_STATE" || true)
    OLD_IFACE=$(conf_get INTERFACE "$INSTALL_STATE" || true)
    [[ -z $OLD_PREFIX || $OLD_PREFIX == "$PREFIX" ]] || die "installed prefix is /$OLD_PREFIX; explicit uninstall/migration is required"
    [[ -z $OLD_IFACE || $OLD_IFACE == "$IFACE" ]] || die "installed interface is $OLD_IFACE; explicit uninstall/migration is required"
fi

for vip in "${VIPS[@]}"; do
    existing_iface=$(ip -o -4 addr show | awk -v ip="$vip" '$4 ~ ("^" ip "/") {print $2; exit}')
    old_owned=${OLD_VIP_OWNERSHIP[$vip]:-}
    if [[ -n $existing_iface ]]; then
        [[ $existing_iface == "$IFACE" ]] || die "$vip already exists on $existing_iface, not $IFACE"
        if [[ $old_owned == yes ]]; then
            VIP_OWNERS+=(yes)
            log "$vip is already present and owned by the prior printproxy installation"
        else
            VIP_OWNERS+=(no)
            warn "$vip pre-existed this installation; uninstall will not remove it"
        fi
    else
        [[ $old_owned != no ]] || die "$vip was recorded as pre-existing but is now missing; refusing to claim it"
        if [[ $old_owned != yes && $MANAGE_VIPS != yes ]]; then
            die "$vip is not configured on this host. Add it through the active network manager, or rerun explicitly with --manage-vips"
        fi
        if arping -D -q -I "$IFACE" -c 3 -w 3 "$vip"; then
            VIP_OWNERS+=(yes)
        else
            die "duplicate-address detection reports $vip already in use"
        fi
    fi
done
VIP_OWNED_CSV=$(IFS=,; printf '%s' "${VIP_OWNERS[*]}")

if systemctl is-active --quiet printproxy.service 2>/dev/null; then
    log 'Active printproxy service detected; listener collision check is deferred to the transactional restart'
else
    for index in "${!VIPS[@]}"; do
        vip=${VIPS[$index]}
        listen_port=${LISTEN_PORTS[$index]}
        if ss -H -ltn4 "sport = :$listen_port" | awk -v endpoint="$vip:$listen_port" '
            $4 == endpoint || $4 == "0.0.0.0:" substr(endpoint, index(endpoint, ":") + 1) { found=1 }
            END { exit !found }
        '; then
            die "listener $vip:$listen_port conflicts with an existing socket; inspect with: ss -lntp"
        fi
    done
fi

log "Non-aggressive printer service probe (TCP connect only):"
PROBE_RESULT=$(python3 - "$PRINTER_IP_CSV" "$PRINTER_PORT_CSV" <<'PY'
import socket, sys
hosts=[item.strip() for item in sys.argv[1].split(",")]
configured_ports=[int(item.strip()) for item in sys.argv[2].split(",")]
for index, (host, configured_port) in enumerate(zip(hosts, configured_ports), 1):
    opened=[]
    print(f"  [proxy-{index:03d}] printer {host}:{configured_port}")
    probes=[]
    for port, name in ((configured_port,"configured RAW"),(515,"LPR"),(631,"IPP")):
        if any(existing_port == port for existing_port, _ in probes):
            continue
        probes.append((port, name))
        try:
            with socket.create_connection((host,port),timeout=1.5):
                print(f"    {port}/tcp {name}: open")
                opened.append(port)
        except OSError as exc:
            print(f"    {port}/tcp {name}: closed/unreachable ({exc.__class__.__name__})")
    print(f"RESULT={index}:{configured_port}:{','.join(map(str, opened))}")
PY
)
printf '%s\n' "$PROBE_RESULT" | grep -v '^RESULT='
for index in "${!PRINTER_IPS[@]}"; do
    printer_ip=${PRINTER_IPS[$index]}
    printer_port=${PRINTER_PORTS[$index]}
    result=$(printf '%s\n' "$PROBE_RESULT" | awk -F= -v wanted=$((index + 1)) '$1=="RESULT" {split($2,p,":"); if(p[1]==wanted){print $2; exit}}')
    opened=${result#*:*:}
    if [[ ,$opened, != *,$printer_port,* ]]; then
        if [[ ,$opened, == *,515,* || ,$opened, == *,631,* ]]; then
            die "printer $printer_ip exposes LPR/IPP but not configured RAW port $printer_port; refusing a blind protocol mismatch"
        fi
        warn "Printer $printer_ip:$printer_port is currently unreachable; other mappings remain independently usable"
    fi
    [[ $printer_port == 9100 ]] || die "proxy-$((index + 1)): PROXY_PROTOCOL=raw currently requires PRINTER_PORT=9100"
done

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

MUTATION_STARTED=yes
PRINTPROXY_UID=$(id -u printproxy)
PRINTPROXY_GID=$(id -g printproxy)
python3 -I - "$PROJECT_DIR" "$DATA_DIR" "$SPOOL_DIR" "$LOG_DIR" \
    "$PRINTPROXY_UID" "$PRINTPROXY_GID" <<'PY' || \
    die 'service directory preparation failed; refuse symlinks and inspect every configured storage component'
import pathlib
import sys

project_dir = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(project_dir))
from printproxy_core import StorageError, secure_prepare_service_directories  # noqa: E402

try:
    secure_prepare_service_directories(
        pathlib.Path(sys.argv[2]),
        pathlib.Path(sys.argv[3]),
        pathlib.Path(sys.argv[4]),
        uid=int(sys.argv[5]),
        gid=int(sys.argv[6]),
    )
except (OSError, StorageError, ValueError) as exc:
    print(f"printproxy secure directory preparation: {exc}", file=sys.stderr)
    raise SystemExit(1) from exc
PY

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
    "$OPT_DIR/printproxy.py" "$OPT_DIR/printproxy_core.py" "$OPT_DIR/receipt_renderer.py" \
    "$OPT_DIR/printproxyctl.py" \
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
install -m 0644 -o root -g root "$PROJECT_DIR/receipt_renderer.py" "$OPT_DIR/receipt_renderer.py"
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
    printf 'SCHEMA_VERSION=4\n'
    printf 'INSTALLED_AT=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)"
    printf 'INTERFACE=%s\n' "$IFACE"
    printf 'NETWORK_BACKEND=%s\n' "$NETWORK_BACKEND"
    printf 'VIP=%s\n' "${VIPS[0]}"
    printf 'VIP_LIST=%s\n' "$VIP_CSV"
    printf 'LISTEN_PORT_LIST=%s\n' "$LISTEN_PORT_CSV"
    printf 'PRINTER_IP_LIST=%s\n' "$PRINTER_IP_CSV"
    printf 'PRINTER_PORT_LIST=%s\n' "$PRINTER_PORT_CSV"
    printf 'DATA_DIR=%s\n' "$DATA_DIR"
    printf 'SPOOL_DIR=%s\n' "$SPOOL_DIR"
    printf 'LOG_DIR=%s\n' "$LOG_DIR"
    printf 'PREFIX=%s\n' "$PREFIX"
    printf 'VIP_OWNED=%s\n' "${VIP_OWNERS[0]}"
    printf 'VIP_OWNED_LIST=%s\n' "$VIP_OWNED_CSV"
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
VIP_RECEIPT=$(mktemp /run/printproxy-vip-added.XXXXXX)
PRINTPROXY_VIP_RECEIPT=$VIP_RECEIPT /usr/local/libexec/printproxy-vip up
mapfile -t VIPS_APPLIED <"$VIP_RECEIPT"
NETWORK_APPLIED=yes
rm -f -- "$VIP_RECEIPT"
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
       python3 - "$VIP_CSV" "$LISTEN_PORT_CSV" <<'PY'
import pathlib, socket, sys
vips=[item.strip() for item in sys.argv[1].split(",")]
ports=[int(item.strip()) for item in sys.argv[2].split(",")]
if len(vips) != len(ports):
    raise SystemExit(1)
try:
    with pathlib.Path("/proc/net/tcp").open("r", encoding="ascii") as handle:
        rows=[line.split() for line in handle]
except (OSError, UnicodeError):
    raise SystemExit(1)
listeners={row[1].upper() for row in rows if len(row) >= 4 and row[3] == "0A"}
for host, port in zip(vips, ports):
    try:
        expected=f"{socket.inet_aton(host)[::-1].hex().upper()}:{port:04X}"
    except OSError:
        raise SystemExit(1)
    if expected not in listeners:
        raise SystemExit(1)
PY
    then
        listener_ready=yes
        break
    fi
    sleep 0.25
done
if [[ $listener_ready != yes ]]; then
    systemctl --no-pager --full status printproxy.service >&2 || true
    ss -H -ltn4 >&2 || true
    journalctl -u printproxy.service -n 30 --no-pager >&2 || true
    die 'one or more configured listener sockets did not enter LISTEN within 10 seconds'
fi
/usr/local/sbin/printproxyctl status || die 'post-install service/head health check failed'
systemctl --no-pager --full status printproxy.service
log "Installed successfully with $PROXY_COUNT proxy mapping(s):"
for index in "${!VIPS[@]}"; do
    log "  proxy-$((index + 1)): ${VIPS[$index]}:${LISTEN_PORTS[$index]} -> ${PRINTER_IPS[$index]}:${PRINTER_PORTS[$index]}"
done
log 'Change the management software destination only after printproxyctl self-test succeeds.'
log 'Rollback is immediate per printer: restore each management-software destination to its corresponding physical printer endpoint.'
INSTALL_COMMITTED=yes
