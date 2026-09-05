#!/usr/bin/env bash
# ==============================================================================
# IPsec S2S Manager
# Version 2.2.0
#
# Purpose:
#   Interactive setup and management of route-based IKEv2/IPsec Site-to-Site
#   tunnels on Debian 13 using strongSwan/swanctl and Linux VTI interfaces.
#
# Supported peers:
#   - UniFi gateways
#   - Debian / strongSwan peers
#
# Main features:
#   - create, install, re-apply, reconnect and diagnose managed S2S tunnels
#   - static IPv4, Dynamic DNS and UniFi wildcard peer endpoints
#   - per-tunnel /30 VTI transfer networks and table 220 return routes
#   - remote-network management with overlap/conflict validation
#   - Debian peer bundles with direct SCP transfer and secure import
#   - tunnel backup / restore
#   - discovery and controlled take-over of existing strongSwan/VTI tunnels
#   - optional UFW integration for IPsec UDP 500 / 4500
#   - optional WireGuard full-tunnel VPN server and client management
#
# Manager state:
#   /root/s2s-manager/
#
# Managed system files:
#   /etc/swanctl/conf.d/s2s-manager-*.conf
#   /usr/local/sbin/s2s-manager-vti-*.sh
#   /etc/systemd/system/s2s-manager-vti-*.service
#
# Safety:
#   - does not enable UFW automatically
#   - validates network, VTI, endpoint and allocation conflicts before changes
#   - previews relevant changes before applying them
#   - keeps per-tunnel PSKs in mode 600 files
#   - external backups and peer bundles are parsed as data, not executed as shell code
# ==============================================================================

set -u
set -o pipefail

VERSION="2.2.0"

STATE_DIR="/root/s2s-manager"
TUNNEL_DIR="${STATE_DIR}/tunnels"
ROUTE_DIR="${STATE_DIR}/routes"
SECRET_DIR="${STATE_DIR}/secrets"
BACKUP_DIR="${STATE_DIR}/backups"
EXPORT_DIR="${STATE_DIR}/exports"

WG_DIR="${STATE_DIR}/wireguard"
WG_CLIENT_DIR="${WG_DIR}/clients"
WG_CLIENT_EXPORT_DIR="${WG_DIR}/exports"
WG_BACKUP_DIR="${WG_DIR}/backups"
WG_SERVER_STATE="${WG_DIR}/server.conf"
WG_SERVER_KEY="${WG_DIR}/server.key"
WG_CONFIG_DIR="/etc/wireguard"
WG_CONFIG="${WG_CONFIG_DIR}/wg0.conf"
WG_SYSCTL_FILE="/etc/sysctl.d/99-s2s-manager-wireguard.conf"
STRONGSWAN_ROUTE_BASED_CONFIG="/etc/strongswan.d/s2s-manager-route-based.conf"
STRONGSWAN_LEGACY_ROUTE_BASED_CONFIG="/etc/strongswan.d/charon/route-based.conf"
WG_INTERFACE_DEFAULT="wg0"
WG_NETWORK_DEFAULT="10.250.0.0/24"
WG_PORT_DEFAULT="51820"
WG_DNS_DEFAULT="1.1.1.1"

UFW_STATE_DIR="${STATE_DIR}/firewall"
UFW_TEMP_DIR="${UFW_STATE_DIR}/temporary"
UFW_TIMER_PREFIX="s2s-manager-ufw-temp"

CRON_STATE_DIR="${STATE_DIR}/cron"
CRON_BACKUP_DIR="${CRON_STATE_DIR}/backups"
CRON_HEADER_MARKER="# S2S-MANAGER-CRON-FILE: 1"

SAMBA_STATE_DIR="${STATE_DIR}/samba"
SAMBA_BACKUP_DIR="${SAMBA_STATE_DIR}/backups"
SAMBA_SHARE_DIR="${SAMBA_STATE_DIR}/shares"
SAMBA_CONFIG="/etc/samba/smb.conf"
SAMBA_MANAGER_CONFIG="/etc/samba/s2s-manager-shares.conf"
SAMBA_INCLUDE_LINE="include = ${SAMBA_MANAGER_CONFIG}"

SWANCTL_DIR="/etc/swanctl/conf.d"
MANAGED_PREFIX="s2s-manager"
VTI_SCRIPT_DIR="/usr/local/sbin"
SYSTEMD_DIR="/etc/systemd/system"

REQUIRED_PACKAGES=(
    strongswan
    charon-systemd
    strongswan-swanctl
    libstrongswan-standard-plugins
    libstrongswan-extra-plugins
)

DEFAULT_NET_PREFIX_A=10
DEFAULT_NET_PREFIX_B=200
DEFAULT_NET_START_C=201
DEFAULT_VTI_KEY=42

# ==============================================================================
# Colors
# ==============================================================================

if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'
    C_BOLD=$'\033[1m'
    C_DIM=$'\033[2m'
    C_RED=$'\033[31m'
    C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'
    C_BLUE=$'\033[34m'
    C_CYAN=$'\033[36m'
else
    C_RESET=""
    C_BOLD=""
    C_DIM=""
    C_RED=""
    C_GREEN=""
    C_YELLOW=""
    C_BLUE=""
    C_CYAN=""
fi

# ==============================================================================
# UI
# ==============================================================================

clear_screen() {
    printf '\033c'
}

line() {
    printf '%b\n' "${C_DIM}──────────────────────────────────────────────────────────────${C_RESET}"
}

ok() {
    printf '%b\n' "${C_GREEN}[✓]${C_RESET} $*"
}

warn() {
    printf '%b\n' "${C_YELLOW}[!]${C_RESET} $*"
}

error() {
    printf '%b\n' "${C_RED}[✗]${C_RESET} $*"
}

info() {
    printf '%b\n' "${C_CYAN}[i]${C_RESET} $*"
}

validation_error_block() {
    local title="$1"
    shift

    echo
    printf '%b\n' "${C_RED}${C_BOLD}──────────────────────────────────────────────────────────────${C_RESET}"
    printf '%b\n' "${C_RED}${C_BOLD}  ✗ ${title}${C_RESET}"
    printf '%b\n' "${C_RED}${C_BOLD}──────────────────────────────────────────────────────────────${C_RESET}"

    local message
    for message in "$@"; do
        printf '%b\n' "${C_RED}${message}${C_RESET}"
    done

    printf '%b\n' "${C_RED}${C_BOLD}──────────────────────────────────────────────────────────────${C_RESET}"
    echo
}

validation_success() {
    printf '%b\n' "${C_GREEN}${C_BOLD}[✓] $*${C_RESET}"
}

pause() {
    echo
    read -r -p "Press ENTER to continue..." _
}

banner() {
    clear_screen

    local width=62
    local title="IPsec S2S Manager"
    local version_text="Version ${VERSION}"
    local left right

    printf '%b' "${C_CYAN}${C_BOLD}"
    printf '╔%s╗\n' "$(printf '═%.0s' $(seq 1 ${width}))"

    left=$(( (width - ${#title}) / 2 ))
    right=$(( width - ${#title} - left ))
    printf '║%*s%s%*s║\n' "${left}" '' "${title}" "${right}" ''

    left=$(( (width - ${#version_text}) / 2 ))
    right=$(( width - ${#version_text} - left ))
    printf '║%*s%s%*s║\n' "${left}" '' "${version_text}" "${right}" ''

    printf '╚%s╝\n' "$(printf '═%.0s' $(seq 1 ${width}))"
    printf '%b' "${C_RESET}"
    echo
    printf 'State directory: %b%s%b\n' "${C_CYAN}" "${STATE_DIR}" "${C_RESET}"
    echo
}

show_server_identity_summary() {
    local server_hostname primary_ipv4 interface cidr found=0 marker
    server_hostname="$(hostname 2>/dev/null || true)"
    if [[ -z "${server_hostname}" && -r /etc/hostname ]]; then
        server_hostname="$(head -1 /etc/hostname 2>/dev/null || true)"
    fi
    primary_ipv4="$(detect_public_ipv4)"

    printf '%-20s %s\n' "Server hostname:" "${server_hostname:-unknown}"
    printf '%-20s %s\n' "Primary IPv4:" "${primary_ipv4:-not detected}"
    printf '%-20s' "IPv4 addresses:"

    while read -r interface cidr; do
        [[ -n "${interface}" && -n "${cidr}" ]] || continue
        interface="${interface%%@*}"
        [[ "${interface}" == "lo" ]] && continue
        marker=""
        [[ "${cidr%%/*}" == "${primary_ipv4}" ]] && marker=" [primary]"
        if (( found == 0 )); then
            printf ' %s  %s%s\n' "${interface}" "${cidr}" "${marker}"
        else
            printf '%-20s %s  %s%s\n' "" "${interface}" "${cidr}" "${marker}"
        fi
        found=1
    done < <(ip -o -4 addr show scope global 2>/dev/null | awk '{print $2, $4}')

    if (( found == 0 )); then
        printf ' none detected\n'
    fi
    echo
}

section() {
    echo
    line
    printf '  %b%s%b\n' "${C_BOLD}${C_CYAN}" "$1" "${C_RESET}"
    line
    echo
}

menu_group_header() {
    local title="$1"
    local color="$2"
    local width=60

    echo
    printf '  %b%s%b\n' "${C_BOLD}${color}" "${title}" "${C_RESET}"
    printf '  %b' "${color}"
    table_divider_segment "${width}"
    printf '%b\n' "${C_RESET}"
}


visible_length() {
    local value="$1"
    # Strip ANSI CSI color/style sequences before measuring.
    value="$(printf '%s' "${value}" | sed -E $'s/\033\\[[0-9;]*[[:alpha:]]//g')"
    printf '%d' "${#value}"
}

pad_ansi_right() {
    local value="$1"
    local width="$2"
    local len pad

    len="$(visible_length "${value}")"
    pad=$(( width - len ))
    (( pad < 0 )) && pad=0

    printf '%b' "${value}"
    printf '%*s' "${pad}" ''
}

menu_block_line() {
    local color="$1"
    local title="$2"
    local width="$3"

    printf '%b' "${C_BOLD}${color}"
    printf '  %s' "${title}"
    printf '%b' "${C_RESET}"
    local used=$(( 2 + ${#title} ))
    if (( used < width )); then
        printf '%*s' "$(( width - used ))" ''
    fi
}

menu_block_rule() {
    local color="$1"
    local width="$2"

    printf '  %b' "${color}"
    table_divider_segment "$(( width - 2 ))"
    printf '%b' "${C_RESET}"
}

render_menu_pair() {
    local left_title="$1"
    local left_color="$2"
    local left_items_name="$3"
    local right_title="$4"
    local right_color="$5"
    local right_items_name="$6"

    local -n left_items="${left_items_name}"
    local -n right_items="${right_items_name}"

    # Fixed terminal columns. The right block always begins at column 65,
    # so long left-hand labels can never shift [13], [14], etc.
    local right_col=65
    local rule_width=56
    local rows i left right

    (( ${#left_items[@]} > ${#right_items[@]} )) && rows=${#left_items[@]} || rows=${#right_items[@]}

    echo

    printf '%b  %s%b' "${C_BOLD}${left_color}" "${left_title}" "${C_RESET}"
    printf '\033[%dG' "${right_col}"
    printf '%b  %s%b\n' "${C_BOLD}${right_color}" "${right_title}" "${C_RESET}"

    printf '  %b' "${left_color}"
    table_divider_segment "${rule_width}"
    printf '%b' "${C_RESET}"
    printf '\033[%dG' "${right_col}"
    printf '  %b' "${right_color}"
    table_divider_segment "${rule_width}"
    printf '%b\n' "${C_RESET}"

    for ((i=0; i<rows; i++)); do
        left="${left_items[$i]:-}"
        right="${right_items[$i]:-}"

        printf '%s' "${left}"
        printf '\033[%dG' "${right_col}"
        printf '%s\n' "${right}"
    done
}

confirm_yes_no() {
    local prompt="$1"
    local default="${2:-N}"
    local answer

    if [[ "${default}" == "Y" ]]; then
        read -r -p "${prompt} [Y/n]: " answer
        [[ -z "${answer}" || "${answer}" =~ ^[Yy]$ ]]
    else
        read -r -p "${prompt} [y/N]: " answer
        [[ "${answer}" =~ ^[Yy]$ ]]
    fi
}

# ==============================================================================
# Environment / package checks
# ==============================================================================


swanctl_clean() {
    # Hide the known harmless swanctl agent-plugin warning on Debian 13.
    # Keep all other stdout/stderr output intact.
    "$@" 2>&1 | sed \
        -e '/^agent plugin requires CAP_SETUID\/CAP_SETGID capability$/d' \
        -e "/^plugin 'agent': failed to load - agent_plugin_create returned NULL$/d"
    local rc=${PIPESTATUS[0]}
    return "${rc}"
}


ensure_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        error "This manager must be run as root."
        exit 1
    fi
}

init_state_dirs() {
    mkdir -p "${TUNNEL_DIR}" "${ROUTE_DIR}" "${SECRET_DIR}" "${BACKUP_DIR}" "${EXPORT_DIR}" \
        "${WG_DIR}" "${WG_CLIENT_DIR}" "${WG_CLIENT_EXPORT_DIR}" "${WG_BACKUP_DIR}" \
        "${UFW_STATE_DIR}" "${UFW_TEMP_DIR}" "${CRON_STATE_DIR}" "${CRON_BACKUP_DIR}" \
        "${SAMBA_STATE_DIR}" "${SAMBA_BACKUP_DIR}" "${SAMBA_SHARE_DIR}"
    chmod 700 "${STATE_DIR}" "${TUNNEL_DIR}" "${ROUTE_DIR}" "${SECRET_DIR}" "${BACKUP_DIR}" "${EXPORT_DIR}" \
        "${WG_DIR}" "${WG_CLIENT_DIR}" "${WG_CLIENT_EXPORT_DIR}" "${WG_BACKUP_DIR}" \
        "${UFW_STATE_DIR}" "${UFW_TEMP_DIR}" "${CRON_STATE_DIR}" "${CRON_BACKUP_DIR}" \
        "${SAMBA_STATE_DIR}" "${SAMBA_BACKUP_DIR}" "${SAMBA_SHARE_DIR}"
}

debian_major_version() {
    if [[ -r /etc/os-release ]]; then
        . /etc/os-release
        if [[ "${ID:-}" == "debian" ]]; then
            printf '%s' "${VERSION_ID:-unknown}"
            return
        fi
    fi
    printf 'unknown'
}

package_installed() {
    local status
    status="$(dpkg-query -W -f='${Status}' "$1" 2>/dev/null || true)"
    grep -q '^install ok installed$' <<< "${status}"
}

missing_packages() {
    local pkg
    for pkg in "${REQUIRED_PACKAGES[@]}"; do
        package_installed "${pkg}" || printf '%s\n' "${pkg}"
    done
}

command_available() {
    command -v "$1" >/dev/null 2>&1
}

table220_default_route() {
    ip -4 route show table 220 default 2>/dev/null || true
}

detect_public_ipv4() {
    local detected=""

    detected=$(
        ip -4 route get 1.1.1.1 2>/dev/null |
        awk '{
            for (i=1; i<=NF; i++) {
                if ($i == "src") {
                    print $(i+1)
                    exit
                }
            }
        }'
    )

    printf '%s' "${detected}"
}

tpm_disabled() {
    grep -Eq '^[[:space:]]*load[[:space:]]*=[[:space:]]*no[[:space:]]*$' \
        /etc/strongswan.d/charon/tpm.conf 2>/dev/null
}

agent_disabled() {
    grep -Eq '^[[:space:]]*load[[:space:]]*=[[:space:]]*no[[:space:]]*$' \
        /etc/strongswan.d/charon/agent.conf 2>/dev/null
}

route_based_global_ready() {
    grep -Eq '^[[:space:]]*install_routes[[:space:]]*=[[:space:]]*no[[:space:]]*$' \
        "${STRONGSWAN_ROUTE_BASED_CONFIG}" 2>/dev/null
}

ufw_installed() {
    command_available ufw
}

ufw_active() {
    local status
    ufw_installed || return 1
    status="$(ufw status 2>/dev/null || true)"
    grep -q '^Status: active' <<< "${status}"
}

valid_port() {
    local port="$1"
    local number
    [[ "${port}" =~ ^[0-9]+$ ]] || return 1
    number=$((10#${port}))
    (( number >= 1 && number <= 65535 ))
}

detect_ssh_port() {
    local ssh_port=""

    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        ssh_port="$(awk '{print $4}' <<< "${SSH_CONNECTION}")"
    fi
    if ! valid_port "${ssh_port}" && command_available sshd; then
        ssh_port="$(sshd -T 2>/dev/null | awk '$1=="port"{print $2; exit}')"
    fi
    valid_port "${ssh_port}" || ssh_port="22"

    printf '%s' "${ssh_port}"
}

preflight_ready() {
    [[ "$(debian_major_version)" == "13" ]] || return 1
    command_available ip || return 1
    command_available openssl || return 1
    command_available swanctl || return 1

    local missing
    missing="$(missing_packages)"
    [[ -z "${missing}" ]] || return 1

    tpm_disabled || return 1
    # The agent plugin is optional for this manager. If it is not disabled,
    # show a warning in pre-flight but do not block read-only/import or tunnel
    # management on an otherwise working system.
    route_based_global_ready || return 1

    return 0
}

show_preflight() {
    local display_mode="${1:-standalone}"
    [[ "${display_mode}" == "embedded" ]] || banner
    section "SYSTEM PRE-FLIGHT CHECK"

    local ready=1
    local version
    version="$(debian_major_version)"

    if [[ "${version}" == "13" ]]; then
        ok "Debian 13 detected"
    else
        error "Debian 13 required (detected: ${version})"
        ready=0
    fi

    if [[ "${EUID}" -eq 0 ]]; then
        ok "Running as root"
    else
        error "Root privileges required"
        ready=0
    fi

    if command_available ip; then
        ok "iproute2 / ip command available"
    else
        error "ip command missing"
        ready=0
    fi

    if command_available openssl; then
        ok "OpenSSL available"
    else
        error "OpenSSL missing"
        ready=0
    fi

    echo
    printf '%b\n' "${C_BOLD}Required packages:${C_RESET}"

    local pkg
    for pkg in "${REQUIRED_PACKAGES[@]}"; do
        if package_installed "${pkg}"; then
            ok "${pkg}"
        else
            error "${pkg} - NOT INSTALLED"
            ready=0
        fi
    done

    echo
    printf '%b\n' "${C_BOLD}strongSwan preparation:${C_RESET}"

    if command_available swanctl; then
        ok "swanctl available"
    else
        error "swanctl missing"
        ready=0
    fi

    if tpm_disabled; then
        ok "Unused TPM plugin disabled"
    else
        error "TPM plugin is not disabled by the manager"
        ready=0
    fi

    if agent_disabled; then
        ok "Unused agent plugin disabled for charon"
    else
        warn "Agent plugin is not disabled for charon (optional)"
        echo "    Existing strongSwan tunnels can still be discovered and managed."
        echo "    The manager filters the known harmless swanctl agent warning."
    fi

    if route_based_global_ready; then
        ok "Route-based strongSwan mode prepared"
    else
        error "Route-based strongSwan setting missing"
        ready=0
    fi

    echo
    printf '%b\n' "${C_BOLD}Firewall:${C_RESET}"

    if ufw_installed; then
        ok "UFW installed"
        if ufw_active; then
            ok "UFW active"
        else
            warn "UFW installed but inactive"
        fi
    else
        info "Local UFW not installed (optional)"
        echo "    External/provider firewall can be used instead."
        echo "    Required for IPsec: UDP 500 and UDP 4500"
    fi

    echo
    printf '%b\n' "${C_BOLD}Detected server IPv4:${C_RESET}"
    local public_ip
    public_ip="$(detect_public_ipv4)"
    if [[ -n "${public_ip}" ]]; then
        ok "${public_ip}"
    else
        warn "Could not determine a local IPv4 automatically"
    fi

    echo
    if (( ready == 1 )); then
        ok "System is READY for S2S tunnel management."
        return 0
    fi

    warn "System setup / repair is required before tunnels can be installed."
    return 1
}

install_or_repair_prerequisites() {
    banner
    section "INSTALL / REPAIR PREREQUISITES"

    echo "The following shared prerequisites will be prepared:"
    echo
    echo "Packages:"
    local pkg
    for pkg in "${REQUIRED_PACKAGES[@]}"; do
        if package_installed "${pkg}"; then
            printf '  = %-38s already installed\n' "${pkg}"
        else
            printf '  + %-38s install\n' "${pkg}"
        fi
    done

    echo
    echo "strongSwan:"
    echo "  + disable unused TPM plugin"
    echo "  + disable unused agent plugin"
    echo "  + disable automatic strongSwan route installation"
    echo "  + restart strongSwan"
    echo
    echo "No tunnel will be created by this step."
    echo "No firewall rule will be added by this step."
    echo

    confirm_yes_no "Apply prerequisite setup?" "N" || return

    echo
    section "APPLYING PREREQUISITES"

    local -a missing=()
    mapfile -t missing < <(missing_packages)

    if (( ${#missing[@]} > 0 )); then
        printf '[1/5] Installing required packages... '
        if apt-get update >/tmp/s2s-manager-apt-update.log 2>&1 &&
           DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}" \
               >/tmp/s2s-manager-apt-install.log 2>&1; then
            printf '%b\n' "${C_GREEN}OK${C_RESET}"
        else
            printf '%b\n' "${C_RED}FAILED${C_RESET}"
            error "Package installation failed."
            echo "See:"
            echo "  /tmp/s2s-manager-apt-update.log"
            echo "  /tmp/s2s-manager-apt-install.log"
            pause
            return 1
        fi
    else
        printf '[1/5] Installing required packages... %b\n' "${C_GREEN}ALREADY OK${C_RESET}"
    fi

    printf '[2/5] Disabling unused TPM plugin... '
    mkdir -p /etc/strongswan.d/charon
    cat > /etc/strongswan.d/charon/tpm.conf <<'EOF'
tpm {
    load = no
}
EOF
    printf '%b\n' "${C_GREEN}OK${C_RESET}"

    printf '[3/5] Disabling unused agent plugin... '
    cat > /etc/strongswan.d/charon/agent.conf <<'EOF'
agent {
    load = no
}
EOF
    printf '%b\n' "${C_GREEN}OK${C_RESET}"

    printf '[4/5] Preparing route-based strongSwan mode... '
    cat > "${STRONGSWAN_ROUTE_BASED_CONFIG}" <<'EOF'
charon {
    install_routes = no
}
EOF
    # Versions through 1.3.18 placed this top-level charon block inside the
    # charon plugin include directory, where it was nested incorrectly and had
    # no effect. Remove only that exact manager legacy file.
    rm -f -- "${STRONGSWAN_LEGACY_ROUTE_BASED_CONFIG}"
    printf '%b\n' "${C_GREEN}OK${C_RESET}"

    printf '[5/5] Restarting and validating strongSwan... '
    if systemctl restart strongswan >/tmp/s2s-manager-strongswan-restart.log 2>&1 &&
       systemctl is-active --quiet strongswan; then
        printf '%b\n' "${C_GREEN}OK${C_RESET}"
    else
        printf '%b\n' "${C_RED}FAILED${C_RESET}"
        error "strongSwan did not restart successfully."
        journalctl -u strongswan -n 30 --no-pager
        pause
        return 1
    fi

    echo
    local recent_strongswan
    recent_strongswan="$(journalctl -u strongswan --since "1 minute ago" --no-pager 2>/dev/null || true)"
    if grep -qi "failed to load" <<< "${recent_strongswan}"; then
        warn "Recent strongSwan plugin load errors were found:"
        grep -i "failed to load" <<< "${recent_strongswan}"
    else
        ok "No recent strongSwan plugin load errors."
    fi

    echo
    ok "Prerequisites are prepared."
    pause
}

# ==============================================================================
# IPv4 / CIDR helpers
# ==============================================================================

valid_ipv4() {
    local ip="$1"
    local IFS=.
    local -a octets
    read -r -a octets <<< "${ip}"

    [[ ${#octets[@]} -eq 4 ]] || return 1

    local o
    for o in "${octets[@]}"; do
        [[ "${o}" =~ ^[0-9]+$ ]] || return 1
        (( o >= 0 && o <= 255 )) || return 1
    done
}

ipv4_to_int() {
    local ip="$1"
    local a b c d
    IFS=. read -r a b c d <<< "${ip}"
    printf '%u' "$(( (a << 24) + (b << 16) + (c << 8) + d ))"
}

int_to_ipv4() {
    local n="$1"
    printf '%d.%d.%d.%d' \
        $(( (n >> 24) & 255 )) \
        $(( (n >> 16) & 255 )) \
        $(( (n >> 8) & 255 )) \
        $(( n & 255 ))
}

normalize_30_network() {
    local input="$1"
    local ip prefix n network

    if [[ "${input}" == */* ]]; then
        ip="${input%%/*}"
        prefix="${input##*/}"
    else
        ip="${input}"
        prefix="30"
    fi

    valid_ipv4 "${ip}" || return 1
    [[ "${prefix}" == "30" ]] || return 2

    n=$(ipv4_to_int "${ip}")
    network=$(( n & 0xFFFFFFFC ))
    printf '%s/30' "$(int_to_ipv4 "${network}")"
}

calculate_30_addresses() {
    local network="$1"
    local base="${network%%/*}"
    local n
    n=$(ipv4_to_int "${base}")

    CALC_NETWORK="$(int_to_ipv4 "${n}")/30"
    CALC_DEBIAN="$(int_to_ipv4 "$((n + 1))")"
    CALC_UNIFI="$(int_to_ipv4 "$((n + 2))")"
    CALC_BROADCAST="$(int_to_ipv4 "$((n + 3))")"
}

network_is_exact_base() {
    local input="$1"
    local normalized
    normalized=$(normalize_30_network "${input}") || return 1
    [[ "${input%%/*}" == "${normalized%%/*}" ]]
}

valid_cidr() {
    local input="$1"
    local ip prefix

    [[ "${input}" == */* ]] || return 1
    ip="${input%%/*}"
    prefix="${input##*/}"

    valid_ipv4 "${ip}" || return 1
    [[ "${prefix}" =~ ^[0-9]+$ ]] || return 1
    (( prefix >= 0 && prefix <= 32 ))
}

cidr_network_int() {
    local cidr="$1"
    local ip="${cidr%%/*}"
    local prefix="${cidr##*/}"
    local ipn mask

    ipn="$(ipv4_to_int "${ip}")"
    if (( prefix == 0 )); then
        mask=0
    else
        mask=$(( (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF ))
    fi
    printf '%u' "$(( ipn & mask ))"
}

cidr_broadcast_int() {
    local cidr="$1"
    local prefix="${cidr##*/}"
    local network mask

    network="$(cidr_network_int "${cidr}")"
    if (( prefix == 0 )); then
        mask=0
    else
        mask=$(( (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF ))
    fi
    printf '%u' "$(( network | ((~mask) & 0xFFFFFFFF) ))"
}

cidr_is_exact_network() {
    local cidr="$1"
    valid_cidr "${cidr}" || return 1
    (( $(ipv4_to_int "${cidr%%/*}") == $(cidr_network_int "${cidr}") ))
}

cidr_normalized() {
    local cidr="$1"
    valid_cidr "${cidr}" || return 1
    printf '%s/%s' "$(int_to_ipv4 "$(cidr_network_int "${cidr}")")" "${cidr##*/}"
}

cidr_overlaps() {
    local a="$1" b="$2"
    valid_cidr "${a}" || return 1
    valid_cidr "${b}" || return 1

    local as ae bs be
    as="$(cidr_network_int "${a}")"
    ae="$(cidr_broadcast_int "${a}")"
    bs="$(cidr_network_int "${b}")"
    be="$(cidr_broadcast_int "${b}")"
    (( as <= be && bs <= ae ))
}

route_token_to_cidr() {
    local token="$1"
    case "${token}" in
        default|local|broadcast|unreachable|prohibit|blackhole|throw|nat|multicast|anycast)
            return 1 ;;
    esac

    if [[ "${token}" == */* ]]; then
        valid_cidr "${token}" || return 1
        printf '%s' "${token}"
    elif valid_ipv4 "${token}"; then
        printf '%s/32' "${token}"
    else
        return 1
    fi
}

valid_tunnel_name() {
    [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$ ]]
}

valid_auth_id() {
    [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$ ]]
}

# ==============================================================================
# Safe external key/value parsing
# ==============================================================================

decode_printf_q_value() {
    local raw="$1"
    local out="" body="" ch="" next="" esc="" digits=""
    local i=0 len=0 j=0 max=0

    # printf %q uses '' for the empty string.
    if [[ "${raw}" == "''" ]]; then
        printf ''
        return 0
    fi

    # ANSI-C quoted form used by printf %q for e.g. UTF-8/control bytes.
    if [[ "${raw}" == "\$'"*"'" ]]; then
        body="${raw:2:${#raw}-3}"
        len=${#body}

        while (( i < len )); do
            ch="${body:i:1}"
            if [[ "${ch}" != '\' ]]; then
                out+="${ch}"
                ((i += 1))
                continue
            fi

            ((i += 1))
            (( i < len )) || return 1
            esc="${body:i:1}"

            case "${esc}" in
                a) out+=$'\a'; ((i += 1)) ;;
                b) out+=$'\b'; ((i += 1)) ;;
                e|E) out+=$'\e'; ((i += 1)) ;;
                f) out+=$'\f'; ((i += 1)) ;;
                n) out+=$'\n'; ((i += 1)) ;;
                r) out+=$'\r'; ((i += 1)) ;;
                t) out+=$'\t'; ((i += 1)) ;;
                v) out+=$'\v'; ((i += 1)) ;;
                \\) out+='\' ; ((i += 1)) ;;
                \') out+="'" ; ((i += 1)) ;;
                \") out+='"' ; ((i += 1)) ;;
                x)
                    ((i += 1))
                    digits=""
                    for ((j=0; j<2 && i<len; j++)); do
                        ch="${body:i:1}"
                        [[ "${ch}" =~ ^[0-9A-Fa-f]$ ]] || break
                        digits+="${ch}"
                        ((i += 1))
                    done
                    [[ -n "${digits}" ]] || return 1
                    printf -v ch '%b' "\\x${digits}"
                    out+="${ch}"
                    ;;
                [0-7])
                    digits="${esc}"
                    ((i += 1))
                    for ((j=1; j<3 && i<len; j++)); do
                        ch="${body:i:1}"
                        [[ "${ch}" =~ ^[0-7]$ ]] || break
                        digits+="${ch}"
                        ((i += 1))
                    done
                    printf -v ch '%b' "\\${digits}"
                    out+="${ch}"
                    ;;
                *)
                    # Unknown ANSI-C escape: reject instead of guessing.
                    return 1
                    ;;
            esac
        done

        printf '%s' "${out}"
        return 0
    fi

    # Normal printf %q form: shell metacharacters are escaped with a backslash.
    # Decode backslash-next-char literally; never execute the result.
    len=${#raw}
    while (( i < len )); do
        ch="${raw:i:1}"
        if [[ "${ch}" == '\' ]]; then
            ((i += 1))
            (( i < len )) || return 1
            next="${raw:i:1}"
            out+="${next}"
            ((i += 1))
        else
            out+="${ch}"
            ((i += 1))
        fi
    done

    printf '%s' "${out}"
}

safe_assignment_value() {
    local file="$1"
    local wanted="$2"
    local line="" found=0 raw=""

    [[ -f "${file}" ]] || return 1
    [[ "${wanted}" =~ ^[A-Z0-9_]+$ ]] || return 1

    while IFS= read -r line || [[ -n "${line}" ]]; do
        [[ "${line}" == "${wanted}="* ]] || continue
        ((found += 1))
        (( found == 1 )) || return 1
        raw="${line#*=}"
    done < "${file}"

    (( found == 1 )) || return 1
    decode_printf_q_value "${raw}"
}

read_external_tunnel_config() {
    local file="$1"
    local line key raw value
    local -A seen=()

    [[ -f "${file}" ]] || return 1

    unset EXT_NAME EXT_DISPLAY_NAME EXT_PUBLIC_IP EXT_AUTH_ID EXT_VTI_INTERFACE EXT_VTI_KEY
    unset EXT_VTI_NETWORK EXT_DEBIAN_VTI_IP EXT_UNIFI_VTI_IP EXT_PEER_MODE EXT_PEER_ADDRESS
    unset EXT_PEER_TYPE EXT_CREATED_AT EXT_INSTALLED

    while IFS= read -r line || [[ -n "${line}" ]]; do
        [[ -z "${line}" ]] && continue
        [[ "${line}" =~ ^([A-Z0-9_]+)=(.*)$ ]] || return 1
        key="${BASH_REMATCH[1]}"
        raw="${BASH_REMATCH[2]}"

        case "${key}" in
            NAME|DISPLAY_NAME|PUBLIC_IP|AUTH_ID|VTI_INTERFACE|VTI_KEY|VTI_NETWORK|\
            DEBIAN_VTI_IP|UNIFI_VTI_IP|PEER_MODE|PEER_ADDRESS|PEER_TYPE|CREATED_AT|INSTALLED)
                ;;
            *)
                return 1
                ;;
        esac

        [[ -z "${seen[${key}]:-}" ]] || return 1
        seen["${key}"]=1

        value="$(decode_printf_q_value "${raw}")" || return 1
        [[ "${value}" != *$'\n'* && "${value}" != *$'\r'* ]] || return 1
        printf -v "EXT_${key}" '%s' "${value}"
    done < "${file}"

    [[ -n "${EXT_NAME:-}" ]] || return 1
    [[ -n "${EXT_PUBLIC_IP:-}" ]] || return 1
    [[ -n "${EXT_AUTH_ID:-}" ]] || return 1
    [[ -n "${EXT_VTI_INTERFACE:-}" ]] || return 1
    [[ -n "${EXT_VTI_KEY:-}" ]] || return 1
    [[ -n "${EXT_VTI_NETWORK:-}" ]] || return 1
    [[ -n "${EXT_DEBIAN_VTI_IP:-}" ]] || return 1
    [[ -n "${EXT_UNIFI_VTI_IP:-}" ]] || return 1

    : "${EXT_DISPLAY_NAME:=${EXT_NAME}}"
    : "${EXT_PEER_MODE:=dynamic}"
    : "${EXT_PEER_ADDRESS:=}"
    : "${EXT_PEER_TYPE:=unifi}"
    : "${EXT_INSTALLED:=0}"

    valid_tunnel_name "${EXT_NAME}" || return 1
    valid_display_name "${EXT_DISPLAY_NAME}" || return 1
    valid_ipv4 "${EXT_PUBLIC_IP}" || return 1
    valid_auth_id "${EXT_AUTH_ID}" || return 1
    [[ "${EXT_VTI_INTERFACE}" =~ ^ipsec[0-9]+$ ]] || return 1
    [[ "${EXT_VTI_KEY}" =~ ^[0-9]+$ ]] || return 1
    valid_cidr "${EXT_VTI_NETWORK}" || return 1
    valid_ipv4 "${EXT_DEBIAN_VTI_IP}" || return 1
    valid_ipv4 "${EXT_UNIFI_VTI_IP}" || return 1
    [[ "${EXT_PEER_MODE}" =~ ^(dynamic|static|dns)$ ]] || return 1
    [[ "${EXT_PEER_TYPE}" =~ ^(unifi|debian)$ ]] || return 1
    [[ "${EXT_INSTALLED}" =~ ^[01]$ ]] || return 1

    case "${EXT_PEER_MODE}" in
        dynamic)
            [[ -z "${EXT_PEER_ADDRESS}" ]] || return 1
            ;;
        static)
            valid_ipv4 "${EXT_PEER_ADDRESS}" || return 1
            ;;
        dns)
            valid_hostname "${EXT_PEER_ADDRESS}" || return 1
            ;;
    esac
}

read_peer_bundle() {
    local file="$1"
    local line key raw value
    local -A seen=()

    [[ -f "${file}" ]] || return 1

    unset S2S_PEER_BUNDLE_VERSION CREATED_BY_VERSION CREATED_AT SOURCE_DISPLAY_NAME PEER_DISPLAY_NAME
    unset PUBLIC_IP REMOTE_PUBLIC_IP AUTH_ID VTI_NETWORK LOCAL_VTI_IP REMOTE_VTI_IP PSK

    while IFS= read -r line || [[ -n "${line}" ]]; do
        [[ -z "${line}" ]] && continue
        [[ "${line}" =~ ^([A-Z0-9_]+)=(.*)$ ]] || return 1
        key="${BASH_REMATCH[1]}"
        raw="${BASH_REMATCH[2]}"

        case "${key}" in
            S2S_PEER_BUNDLE_VERSION|CREATED_BY_VERSION|CREATED_AT|SOURCE_DISPLAY_NAME|\
            PEER_DISPLAY_NAME|PUBLIC_IP|REMOTE_PUBLIC_IP|AUTH_ID|VTI_NETWORK|\
            LOCAL_VTI_IP|REMOTE_VTI_IP|PSK)
                ;;
            *)
                return 1
                ;;
        esac

        [[ -z "${seen[${key}]:-}" ]] || return 1
        seen["${key}"]=1

        value="$(decode_printf_q_value "${raw}")" || return 1
        [[ "${value}" != *$'\n'* && "${value}" != *$'\r'* ]] || return 1
        printf -v "${key}" '%s' "${value}"
    done < "${file}"

    [[ "${S2S_PEER_BUNDLE_VERSION:-}" == "1" ]] || return 1
    valid_ipv4 "${PUBLIC_IP:-}" || return 1
    valid_ipv4 "${REMOTE_PUBLIC_IP:-}" || return 1
    valid_auth_id "${AUTH_ID:-}" || return 1
    valid_cidr "${VTI_NETWORK:-}" || return 1
    [[ "${VTI_NETWORK}" =~ /30$ ]] || return 1
    valid_ipv4 "${LOCAL_VTI_IP:-}" || return 1
    valid_ipv4 "${REMOTE_VTI_IP:-}" || return 1
    [[ -n "${PSK:-}" && ${#PSK} -le 1024 ]] || return 1

    [[ -z "${SOURCE_DISPLAY_NAME:-}" ]] || valid_display_name "${SOURCE_DISPLAY_NAME}" || return 1
    [[ -z "${PEER_DISPLAY_NAME:-}" ]] || valid_display_name "${PEER_DISPLAY_NAME}" || return 1
}

# ==============================================================================
# State
# ==============================================================================

tunnel_config_file() { printf '%s/%s.conf' "${TUNNEL_DIR}" "$1"; }
tunnel_route_file()  { printf '%s/%s.routes' "${ROUTE_DIR}" "$1"; }
tunnel_secret_file() { printf '%s/%s.psk' "${SECRET_DIR}" "$1"; }

managed_swan_file() {
    printf '%s/%s-%s.conf' "${SWANCTL_DIR}" "${MANAGED_PREFIX}" "$1"
}

managed_vti_script() {
    printf '%s/%s-vti-%s.sh' "${VTI_SCRIPT_DIR}" "${MANAGED_PREFIX}" "$1"
}

managed_service_file() {
    printf '%s/%s-vti-%s.service' "${SYSTEMD_DIR}" "${MANAGED_PREFIX}" "$1"
}

managed_service_name() {
    printf '%s-vti-%s.service' "${MANAGED_PREFIX}" "$1"
}

tunnel_exists() {
    [[ -f "$(tunnel_config_file "$1")" ]]
}

list_tunnel_names() {
    # Sort by the visible display name. Older definitions without DISPLAY_NAME
    # automatically fall back to their internal NAME via load_tunnel().
    local file name sort_name
    shopt -s nullglob
    for file in "${TUNNEL_DIR}"/*.conf; do
        name="$(basename "${file}" .conf)"
        if load_tunnel "${name}" >/dev/null 2>&1; then
            sort_name="${DISPLAY_NAME:-${NAME:-${name}}}"
        else
            sort_name="${name}"
        fi
        printf '%s\t%s\n' "${sort_name,,}" "${name}"
    done | sort -f -t $'\t' -k1,1 -k2,2 | cut -f2-
    shopt -u nullglob
}

tunnel_count() {
    local count=0 name
    while read -r name; do
        [[ -n "${name}" ]] && ((count += 1))
    done < <(list_tunnel_names)
    printf '%d' "${count}"
}

load_tunnel() {
    local name="$1"
    local file
    file="$(tunnel_config_file "${name}")"
    [[ -f "${file}" ]] || return 1

    unset NAME PUBLIC_IP AUTH_ID VTI_INTERFACE VTI_KEY
    unset VTI_NETWORK DEBIAN_VTI_IP UNIFI_VTI_IP CREATED_AT INSTALLED
    unset MANAGEMENT SOURCE_CONN_NAME SOURCE_SWAN_FILE SOURCE_VTI_SCRIPT
    unset SOURCE_SERVICE SOURCE_FORCED_NATT
    unset PEER_MODE PEER_ADDRESS DISPLAY_NAME PEER_TYPE

    # shellcheck disable=SC1090
    source "${file}"

    : "${INSTALLED:=0}"
    : "${MANAGEMENT:=MANAGED}"
    : "${SOURCE_CONN_NAME:=${MANAGED_PREFIX}-${NAME}}"
    : "${SOURCE_SWAN_FILE:=}"
    : "${SOURCE_VTI_SCRIPT:=}"
    : "${SOURCE_SERVICE:=}"
    : "${SOURCE_FORCED_NATT:=1}"

    # Backward compatibility: all manager states created before v0.30 used
    # a wildcard VTI endpoint and accepted an incoming peer from %any.
    : "${PEER_MODE:=dynamic}"
    : "${PEER_ADDRESS:=}"
    : "${PEER_TYPE:=unifi}"
    : "${DISPLAY_NAME:=${NAME}}"
}

save_tunnel() {
    local name="$1"
    local public_ip="$2"
    local auth_id="$3"
    local interface="$4"
    local key="$5"
    local network="$6"
    local debian_ip="$7"
    local unifi_ip="$8"
    local installed="${9:-0}"
    local peer_mode="${10:-dynamic}"
    local peer_address="${11:-}"
    local display_name="${12:-${name}}"
    local peer_type="${13:-unifi}"

    local config
    config="$(tunnel_config_file "${name}")"

    {
        printf 'NAME=%q\n' "${name}"
        printf 'DISPLAY_NAME=%q\n' "${display_name}"
        printf 'PUBLIC_IP=%q\n' "${public_ip}"
        printf 'AUTH_ID=%q\n' "${auth_id}"
        printf 'VTI_INTERFACE=%q\n' "${interface}"
        printf 'VTI_KEY=%q\n' "${key}"
        printf 'VTI_NETWORK=%q\n' "${network}"
        printf 'DEBIAN_VTI_IP=%q\n' "${debian_ip}"
        printf 'UNIFI_VTI_IP=%q\n' "${unifi_ip}"
        printf 'PEER_MODE=%q\n' "${peer_mode}"
        printf 'PEER_ADDRESS=%q\n' "${peer_address}"
        printf 'PEER_TYPE=%q\n' "${peer_type}"
        printf 'CREATED_AT=%q\n' "$(date -Is)"
        printf 'INSTALLED=%q\n' "${installed}"
    } > "${config}"

    chmod 600 "${config}"
}

save_imported_tunnel() {
    local name="$1"
    local public_ip="$2"
    local auth_id="$3"
    local interface="$4"
    local key="$5"
    local network="$6"
    local debian_ip="$7"
    local unifi_ip="$8"
    local source_conn="$9"
    local source_swan="${10}"
    local source_vti="${11}"
    local source_service="${12}"
    local forced_natt="${13:-0}"

    save_tunnel "${name}" "${public_ip}" "${auth_id}" "${interface}" "${key}"         "${network}" "${debian_ip}" "${unifi_ip}" "1" "dynamic" ""

    cat >> "$(tunnel_config_file "${name}")" <<EOF
MANAGEMENT=IMPORTED
SOURCE_CONN_NAME=$(printf '%q' "${source_conn}")
SOURCE_SWAN_FILE=$(printf '%q' "${source_swan}")
SOURCE_VTI_SCRIPT=$(printf '%q' "${source_vti}")
SOURCE_SERVICE=$(printf '%q' "${source_service}")
SOURCE_FORCED_NATT=$(printf '%q' "${forced_natt}")
EOF

    chmod 600 "$(tunnel_config_file "${name}")"
}

tunnel_connection_name() {
    local name="$1"
    load_tunnel "${name}" || return 1
    if [[ "${MANAGEMENT}" == "IMPORTED" && -n "${SOURCE_CONN_NAME}" ]]; then
        printf '%s' "${SOURCE_CONN_NAME}"
    else
        printf '%s-%s' "${MANAGED_PREFIX}" "${NAME}"
    fi
}

tunnel_is_imported() {
    local name="$1"
    load_tunnel "${name}" || return 1
    [[ "${MANAGEMENT}" == "IMPORTED" ]]
}

imported_readonly_notice() {
    local name="$1"
    load_tunnel "${name}" || return 1

    warn "Tunnel '${NAME}' was imported from an existing external configuration."
    echo "It is currently READ-ONLY in S2S Manager."
    echo
    echo "The original strongSwan/VTI/systemd files are still authoritative."
    echo "Use diagnostics or reconnect safely, but do not change manager-owned"
    echo "configuration until a future Take Over step converts this tunnel."
}

read_routes() {
    local file
    file="$(tunnel_route_file "$1")"
    [[ -f "${file}" ]] && cat "${file}"
}

write_routes() {
    local name="$1"
    shift
    local file route
    file="$(tunnel_route_file "${name}")"
    : > "${file}"
    for route in "$@"; do
        [[ -n "${route}" ]] && printf '%s\n' "${route}" >> "${file}"
    done
    chmod 600 "${file}"
}

save_psk() {
    local file
    file="$(tunnel_secret_file "$1")"
    printf '%s\n' "$2" > "${file}"
    chmod 600 "${file}"
}

read_psk() {
    local file
    file="$(tunnel_secret_file "$1")"
    [[ -f "${file}" ]] || return 1
    cat "${file}"
}

extract_psk_from_swan_file() {
    local file="$1"
    [[ -f "${file}" ]] || return 1

    awk '
        /^[[:space:]]*secret[[:space:]]*=/ {
            v=$0
            sub(/^[^=]*=[[:space:]]*/, "", v)
            sub(/[[:space:]]*$/, "", v)
            if (v ~ /^".*"$/) {
                sub(/^"/, "", v)
                sub(/"$/, "", v)
            }
            print v
            exit
        }
    ' "${file}"
}

strongswan_escape_string() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    printf '%s' "${value}"
}

generate_psk() {
    openssl rand -base64 32 | tr -d '\n'
}

auth_id_in_use() {
    local wanted="$1"
    local ignore="${2:-}"
    local name

    while read -r name; do
        [[ -z "${name}" || "${name}" == "${ignore}" ]] && continue
        load_tunnel "${name}" || continue
        [[ "${AUTH_ID}" == "${wanted}" ]] && return 0
    done < <(list_tunnel_names)

    return 1
}

network_in_use() {
    local wanted="$1"
    local ignore="${2:-}"
    local name

    while read -r name; do
        [[ -z "${name}" || "${name}" == "${ignore}" ]] && continue
        load_tunnel "${name}" || continue
        [[ "${VTI_NETWORK}" == "${wanted}" ]] && return 0
    done < <(list_tunnel_names)

    return 1
}

set_network_conflict() {
    NETWORK_CONFLICT_KIND="$1"
    NETWORK_CONFLICT_WITH="$2"
    NETWORK_CONFLICT_DETAIL="$3"
    NETWORK_CONFLICT_SOURCE="${4:-unknown}"
}

check_manager_network_conflict() {
    local candidate="$1"
    local ignore_tunnel="${2:-}"
    local name route

    while read -r name; do
        [[ -z "${name}" || "${name}" == "${ignore_tunnel}" ]] && continue
        load_tunnel "${name}" || continue

        if cidr_overlaps "${candidate}" "${VTI_NETWORK}"; then
            set_network_conflict "TUNNEL" "${VTI_NETWORK}" \
                "overlaps tunnel transfer network" \
                "S2S Manager tunnel '${NAME}'"
            return 0
        fi

        while read -r route; do
            [[ -z "${route}" ]] && continue
            valid_cidr "${route}" || continue
            if cidr_overlaps "${candidate}" "${route}"; then
                set_network_conflict "REMOTE" "${route}" \
                    "overlaps configured remote network" \
                    "S2S Manager tunnel '${NAME}'"
                return 0
            fi
        done < <(read_routes "${name}")
    done < <(list_tunnel_names)

    return 1
}

check_live_system_route_conflict() {
    local candidate="$1"
    local ignore_interface="${2:-}"
    local line token route dev

    command_available ip || return 1

    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        token="${line%% *}"
        route="$(route_token_to_cidr "${token}" 2>/dev/null || true)"
        [[ -n "${route}" ]] || continue
        [[ "${route}" == "0.0.0.0/0" || "${route}" == "127.0.0.0/8" ]] && continue

        dev="$(awk '{
            for (i=1; i<=NF; i++) {
                if ($i=="dev" && (i+1)<=NF) { print $(i+1); exit }
            }
        }' <<< "${line}")"

        [[ -n "${ignore_interface}" && "${dev}" == "${ignore_interface}" ]] && continue

        if cidr_overlaps "${candidate}" "${route}"; then
            set_network_conflict "SYSTEM" "${route}" \
                "overlaps an existing live Debian route" \
                "Debian routing table${dev:+ (interface ${dev})}"
            return 0
        fi
    done < <(ip -4 route show table all 2>/dev/null)

    return 1
}

check_network_conflict() {
    local candidate="$1"
    local ignore_tunnel="${2:-}"
    local ignore_interface="${3:-}"

    NETWORK_CONFLICT_KIND=""
    NETWORK_CONFLICT_WITH=""
    NETWORK_CONFLICT_DETAIL=""
    NETWORK_CONFLICT_SOURCE=""

    check_manager_network_conflict "${candidate}" "${ignore_tunnel}" && return 0
    check_live_system_route_conflict "${candidate}" "${ignore_interface}" && return 0
    return 1
}

show_network_conflict() {
    validation_error_block \
        "NETWORK CONFLICT" \
        "Requested:       $1" \
        "Conflicts with:  ${NETWORK_CONFLICT_WITH}" \
        "Source:          ${NETWORK_CONFLICT_SOURCE}" \
        "Reason:          ${NETWORK_CONFLICT_DETAIL}"
}

auth_id_in_loaded_swan() {
    local wanted="$1"
    command_available swanctl || return 1

    swanctl_clean swanctl --list-conns 2>/dev/null | awk -v wanted="${wanted}" '
        /remote .*authentication:/ { remote_auth=1; next }
        remote_auth && /^[[:space:]]+id:[[:space:]]*/ {
            line=$0
            sub(/^[[:space:]]+id:[[:space:]]*/, "", line)
            if (line == wanted) found=1
            remote_auth=0
        }
        /^[^[:space:]]/ && $0 !~ /authentication:/ { remote_auth=0 }
        END { exit found ? 0 : 1 }
    '
}

vti_key_in_system_use() {
    local wanted="$1"
    local details
    command_available ip || return 1
    details="$(ip -d link show type vti 2>/dev/null || true)"
    grep -Eq "vti .* (ikey|okey) (0\\.0\\.0\\.)?${wanted}([[:space:]]|$)" <<< "${details}"
}

interface_in_system_use() {
    local iface="$1"
    ip link show "${iface}" >/dev/null 2>&1
}

next_interface_index() {
    local index=0 name used key

    while :; do
        used=0
        key=$((DEFAULT_VTI_KEY + index))

        while read -r name; do
            [[ -z "${name}" ]] && continue
            load_tunnel "${name}" || continue
            if [[ "${VTI_INTERFACE}" == "ipsec${index}" || "${VTI_KEY}" == "${key}" ]]; then
                used=1
                break
            fi
        done < <(list_tunnel_names)

        if (( used == 0 )) &&
           ! interface_in_system_use "ipsec${index}" &&
           ! vti_key_in_system_use "${key}"; then
            printf '%d' "${index}"
            return
        fi

        ((index += 1))
    done
}

next_vti_network() {
    local c candidate
    for (( c=DEFAULT_NET_START_C; c<=250; c++ )); do
        candidate="${DEFAULT_NET_PREFIX_A}.${DEFAULT_NET_PREFIX_B}.${c}.0/30"
        if ! check_network_conflict "${candidate}"; then
            printf '%s' "${candidate}"
            return
        fi
    done
    printf '10.200.251.0/30'
}

vti_current_remote_endpoint() {
    local iface="$1"
    local remote=""

    command_available ip || return 1
    ip link show "${iface}" >/dev/null 2>&1 || return 1

    remote="$(
        ip -d link show "${iface}" 2>/dev/null |
        awk '/vti / {
            for (i=1; i<=NF; i++) {
                if ($i=="remote" && (i+1)<=NF) { print $(i+1); exit }
            }
        }'
    )"

    [[ "${remote}" == "any" ]] && remote="0.0.0.0"
    [[ -n "${remote}" ]] || return 1
    printf '%s' "${remote}"
}

dns_peer_endpoint_status() {
    local name="$1"
    load_tunnel "${name}" || return 1

    DNS_PEER_STATUS="NOT_DNS"
    DNS_PEER_HOSTNAME="${PEER_ADDRESS:-}"
    DNS_PEER_RESOLVED_IP=""
    DNS_PEER_VTI_IP=""
    DNS_PEER_DETAIL=""

    [[ "${PEER_MODE}" == "dns" ]] || return 0

    PEER_RESOLVED_IP=""
    PEER_RESOLVE_MULTIPLE=""
    resolve_peer_hostname "${PEER_ADDRESS}"
    case "$?" in
        0)
            DNS_PEER_RESOLVED_IP="${PEER_RESOLVED_IP}"
            ;;
        1)
            DNS_PEER_STATUS="RESOLVE_FAILED"
            DNS_PEER_DETAIL="hostname currently has no resolvable IPv4 address"
            return 0
            ;;
        2)
            DNS_PEER_STATUS="CHECK_UNAVAILABLE"
            DNS_PEER_DETAIL="getent is unavailable"
            return 0
            ;;
        3)
            DNS_PEER_STATUS="MULTIPLE"
            DNS_PEER_DETAIL="hostname resolves to multiple IPv4 addresses: ${PEER_RESOLVE_MULTIPLE}"
            return 0
            ;;
    esac

    DNS_PEER_VTI_IP="$(vti_current_remote_endpoint "${VTI_INTERFACE}" 2>/dev/null || true)"
    if [[ -z "${DNS_PEER_VTI_IP}" ]]; then
        DNS_PEER_STATUS="VTI_MISSING"
        DNS_PEER_DETAIL="VTI interface is missing or its remote endpoint could not be read"
    elif [[ "${DNS_PEER_VTI_IP}" != "${DNS_PEER_RESOLVED_IP}" ]]; then
        DNS_PEER_STATUS="OUTDATED"
        DNS_PEER_DETAIL="DNS endpoint changed; Re-apply is required"
    else
        DNS_PEER_STATUS="CURRENT"
    fi
}

get_vti_remote_endpoint() {
    local iface="$1"

    command_available ip || return 1
    ip link show "${iface}" >/dev/null 2>&1 || return 1

    local remote
    remote="$(
        ip -d link show "${iface}" 2>/dev/null |
        awk '/vti / {
            for (i=1; i<=NF; i++) {
                if ($i=="remote" && (i+1)<=NF) { print $(i+1); exit }
            }
        }'
    )"

    [[ "${remote}" == "any" ]] && remote="0.0.0.0"
    [[ -n "${remote}" ]] || return 1

    printf '%s' "${remote}"
}

dns_peer_status() {
    local name="$1"
    load_tunnel "${name}" || return 1

    DNS_STATUS="NOT_DNS"
    DNS_CURRENT_IP=""
    DNS_VTI_IP=""
    DNS_STATUS_DETAIL=""

    [[ "${PEER_MODE}" == "dns" ]] || return 0

    PEER_RESOLVED_IP=""
    PEER_RESOLVE_MULTIPLE=""
    resolve_peer_hostname "${PEER_ADDRESS}"
    case "$?" in
        0)
            DNS_CURRENT_IP="${PEER_RESOLVED_IP}"
            ;;
        1)
            DNS_STATUS="UNRESOLVED"
            DNS_STATUS_DETAIL="hostname currently has no resolvable IPv4 address"
            return 0
            ;;
        2)
            DNS_STATUS="CHECK_UNAVAILABLE"
            DNS_STATUS_DETAIL="getent is unavailable"
            return 0
            ;;
        3)
            DNS_STATUS="MULTIPLE"
            DNS_STATUS_DETAIL="hostname resolves to multiple IPv4 addresses: ${PEER_RESOLVE_MULTIPLE}"
            return 0
            ;;
    esac

    if ! DNS_VTI_IP="$(get_vti_remote_endpoint "${VTI_INTERFACE}" 2>/dev/null)"; then
        DNS_STATUS="NO_VTI"
        DNS_STATUS_DETAIL="VTI interface is not currently present"
        return 0
    fi

    if [[ "${DNS_CURRENT_IP}" == "${DNS_VTI_IP}" ]]; then
        DNS_STATUS="CURRENT"
        DNS_STATUS_DETAIL="DNS IPv4 matches the current VTI endpoint"
    else
        DNS_STATUS="OUTDATED"
        DNS_STATUS_DETAIL="DNS IPv4 differs from the current VTI endpoint"
    fi
}

show_dns_summary_warnings() {
    local name found=0
    while read -r name; do
        [[ -z "${name}" ]] && continue
        load_tunnel "${name}" || continue
        [[ "${INSTALLED}" == "1" && "${PEER_MODE}" == "dns" ]] || continue

        dns_peer_status "${name}" || continue
        case "${DNS_STATUS}" in
            OUTDATED)
                (( found == 0 )) && echo
                found=1
                warn "Tunnel '${NAME}' has a changed Dynamic DNS endpoint."
                printf '    Hostname:      %s\n' "${PEER_ADDRESS}"
                printf '    Current DNS:   %s\n' "${DNS_CURRENT_IP}"
                printf '    VTI endpoint:  %s\n' "${DNS_VTI_IP}"
                echo "    Action: Run Re-apply tunnel configuration."
                ;;
            UNRESOLVED|MULTIPLE|CHECK_UNAVAILABLE)
                (( found == 0 )) && echo
                found=1
                warn "Tunnel '${NAME}' has a Dynamic DNS problem."
                printf '    Hostname:      %s\n' "${PEER_ADDRESS}"
                printf '    Reason:        %s\n' "${DNS_STATUS_DETAIL}"
                ;;
        esac
    done < <(list_tunnel_names)
}

peer_ip_used_by_other_tunnel() {
    local candidate_ip="$1"
    local ignore_name="${2:-}"
    local name other_ip

    while read -r name; do
        [[ -z "${name}" || "${name}" == "${ignore_name}" ]] && continue
        load_tunnel "${name}" || continue

        case "${PEER_MODE}" in
            static)
                other_ip="${PEER_ADDRESS}"
                ;;
            dns)
                PEER_RESOLVED_IP=""
                PEER_RESOLVE_MULTIPLE=""
                if resolve_peer_hostname "${PEER_ADDRESS}" >/dev/null 2>&1; then
                    other_ip="${PEER_RESOLVED_IP}"
                else
                    other_ip=""
                fi
                ;;
            dynamic)
                # A wildcard VTI may currently be connected to this IP, but that is
                # not represented as a fixed manager endpoint. Do not treat it as a
                # configuration conflict.
                other_ip=""
                ;;
            *)
                other_ip=""
                ;;
        esac

        if [[ -n "${other_ip}" && "${other_ip}" == "${candidate_ip}" ]]; then
            PEER_IP_MATCH_TUNNEL="${NAME}"
            PEER_IP_MATCH_MODE="${PEER_MODE}"
            return 0
        fi
    done < <(list_tunnel_names)

    return 1
}

tunnel_connection_state() {
    local name="$1"
    local conn
    conn="$(tunnel_connection_name "${name}")" || { printf 'UNKNOWN'; return; }
    local sa base_state

    if ! command_available swanctl; then
        printf 'UNKNOWN'
        return
    fi

    sa="$(swanctl_clean swanctl --list-sas 2>/dev/null || true)"

    if grep -qE "^${conn}: .*ESTABLISHED" <<< "${sa}" && \
       awk -v c="${conn}:" '
           $0 ~ "^" c {show=1; next}
           show && /^[^[:space:]]/ {exit}
           show && /INSTALLED/ {found=1; exit}
           END {exit found ? 0 : 1}
       ' <<< "${sa}"; then
        base_state="CONNECTED"
    else
        base_state="DISCONNECTED"
    fi

    load_tunnel "${name}" >/dev/null 2>&1 || {
        printf '%s' "${base_state}"
        return
    }

    if [[ "${PEER_MODE}" == "dns" && "${INSTALLED}" == "1" ]]; then
        dns_peer_status "${name}" || true
        case "${DNS_STATUS}" in
            OUTDATED|UNRESOLVED|MULTIPLE|CHECK_UNAVAILABLE)
                printf 'DISCONNECTED (DNS)'
                return
                ;;
        esac
    fi

    printf '%s' "${base_state}"
}


# ==============================================================================
# State migration / compatibility repair
# ==============================================================================

bundle_value() {
    local file="$1"
    local key="$2"
    safe_assignment_value "${file}" "${key}"
}

bundle_matches_tunnel_as_debian_peer() {
    local bundle="$1"
    local tunnel_public="$2"
    local tunnel_peer="$3"
    local tunnel_network="$4"
    local tunnel_local_vti="$5"
    local tunnel_remote_vti="$6"

    local b_public b_remote b_network b_local_vti b_remote_vti

    b_public="$(bundle_value "${bundle}" PUBLIC_IP 2>/dev/null || true)"
    b_remote="$(bundle_value "${bundle}" REMOTE_PUBLIC_IP 2>/dev/null || true)"
    b_network="$(bundle_value "${bundle}" VTI_NETWORK 2>/dev/null || true)"
    b_local_vti="$(bundle_value "${bundle}" LOCAL_VTI_IP 2>/dev/null || true)"
    b_remote_vti="$(bundle_value "${bundle}" REMOTE_VTI_IP 2>/dev/null || true)"

    [[ -n "${b_public}" && -n "${b_remote}" && -n "${b_network}" ]] || return 1
    [[ "${b_network}" == "${tunnel_network}" ]] || return 1

    # Match either the source-tunnel orientation or the imported peer orientation.
    if [[ "${b_public}" == "${tunnel_peer}" &&
          "${b_remote}" == "${tunnel_public}" &&
          "${b_local_vti}" == "${tunnel_remote_vti}" &&
          "${b_remote_vti}" == "${tunnel_local_vti}" ]]; then
        return 0
    fi

    if [[ "${b_public}" == "${tunnel_public}" &&
          "${b_remote}" == "${tunnel_peer}" &&
          "${b_local_vti}" == "${tunnel_local_vti}" &&
          "${b_remote_vti}" == "${tunnel_remote_vti}" ]]; then
        return 0
    fi

    return 1
}

repair_peer_type_state_bug() {
    local file name bundle
    local current_type current_mode current_peer current_public current_network
    local current_local_vti current_remote_vti
    local repaired=0

    shopt -s nullglob
    for file in "${TUNNEL_DIR}"/*.conf; do
        name="$(basename "${file}" .conf)"
        load_tunnel "${name}" || continue

        current_type="${PEER_TYPE}"
        current_mode="${PEER_MODE}"
        current_peer="${PEER_ADDRESS}"
        current_public="${PUBLIC_IP}"
        current_network="${VTI_NETWORK}"
        current_local_vti="${DEBIAN_VTI_IP}"
        current_remote_vti="${UNIFI_VTI_IP}"

        # Only tunnels affected by the historical bug are candidates.
        [[ "${current_type}" == "unifi" ]] || continue
        [[ "${current_mode}" == "static" ]] || continue
        valid_ipv4 "${current_peer}" || continue

        for bundle in "${EXPORT_DIR}"/*.s2s-peer /root/s2s-manager-import/*.s2s-peer; do
            [[ -f "${bundle}" ]] || continue
            if bundle_matches_tunnel_as_debian_peer \
                "${bundle}" \
                "${current_public}" "${current_peer}" "${current_network}" \
                "${current_local_vti}" "${current_remote_vti}"; then

                # Rewrite only PEER_TYPE. Everything else stays byte-for-byte equivalent.
                if grep -q '^PEER_TYPE=' "${file}"; then
                    sed -i 's/^PEER_TYPE=.*/PEER_TYPE=debian/' "${file}"
                else
                    printf 'PEER_TYPE=debian\n' >> "${file}"
                fi
                chmod 600 "${file}"
                repaired=1
                break
            fi
        done
    done
    shopt -u nullglob

    return $(( repaired == 1 ? 0 : 1 ))
}

# ==============================================================================
# Tunnel list / selection
# ==============================================================================

truncate_table_value() {
    local value="$1"
    local width="$2"

    if (( ${#value} <= width )); then
        printf '%s' "${value}"
    elif (( width > 3 )); then
        printf '%s...' "${value:0:$((width - 3))}"
    else
        printf '%.*s' "${width}" "${value}"
    fi
}

print_table_cell() {
    local value="$1"
    local width="$2"
    local prefix="${3:-}"
    local suffix="${4:-}"
    local display pad

    display="$(truncate_table_value "${value}" "${width}")"
    pad=$(( width - ${#display} ))
    (( pad < 0 )) && pad=0

    printf '%b%s%b' "${prefix}" "${display}" "${suffix}"
    printf '%*s' "${pad}" ''
}

table_divider_segment() {
    local width="$1"
    local i
    for ((i=0; i<width; i++)); do
        printf '─'
    done
}

show_existing_tunnels() {
    local count
    count="$(tunnel_count)"

    if (( count == 0 )); then
        info "No tunnels configured."
        return
    fi

    local number_width=4
    local name_width=22
    local interface_width=10
    local network_width=20
    local management_width=22
    local connection_width=18
    local auth_width=24
    local gap="  "

    # Header. print_table_cell() pads by Bash character count instead of
    # printf byte width, so UTF-8 characters in later rows cannot shift columns.
    print_table_cell "#" "${number_width}"
    printf '%s' "${gap}"
    print_table_cell "Name" "${name_width}"
    printf '%s' "${gap}"
    print_table_cell "Interface" "${interface_width}"
    printf '%s' "${gap}"
    print_table_cell "Tunnel Network" "${network_width}"
    printf '%s' "${gap}"
    print_table_cell "Management" "${management_width}"
    printf '%s' "${gap}"
    print_table_cell "Connection" "${connection_width}"
    printf '%s' "${gap}"
    print_table_cell "Authentication ID" "${auth_width}"
    printf '\n'

    table_divider_segment "${number_width}"
    printf '%s' "${gap}"
    table_divider_segment "${name_width}"
    printf '%s' "${gap}"
    table_divider_segment "${interface_width}"
    printf '%s' "${gap}"
    table_divider_segment "${network_width}"
    printf '%s' "${gap}"
    table_divider_segment "${management_width}"
    printf '%s' "${gap}"
    table_divider_segment "${connection_width}"
    printf '%s' "${gap}"
    table_divider_segment "${auth_width}"
    printf '\n'

    local index=1 name management connection
    local -a dns_notices=()
    while read -r name; do
        [[ -z "${name}" ]] && continue
        load_tunnel "${name}" || continue

        actual_install_state "${name}" || true
        management="$(actual_install_state_label "${ACTUAL_INSTALL_STATE}")"

        case "${ACTUAL_INSTALL_STATE}" in
            INSTALLED|IMPORTED)
                connection="$(tunnel_connection_state "${NAME}")"
                if [[ "${PEER_MODE}" == "dns" ]]; then
                    dns_peer_endpoint_status "${NAME}" || true
                    case "${DNS_PEER_STATUS}" in
                        OUTDATED|RESOLVE_FAILED|CHECK_UNAVAILABLE|MULTIPLE|VTI_MISSING)
                            connection="DISCONNECTED (DNS)"
                            dns_notices+=("${DISPLAY_NAME}|${DNS_PEER_STATUS}|${DNS_PEER_HOSTNAME}|${DNS_PEER_RESOLVED_IP}|${DNS_PEER_VTI_IP}|${DNS_PEER_DETAIL}")
                            ;;
                    esac
                fi
                ;;
            PARTIAL)
                connection="BROKEN"
                ;;
            *)
                connection="-"
                ;;
        esac

        print_table_cell "${index}" "${number_width}"
        printf '%s' "${gap}"
        print_table_cell "${DISPLAY_NAME}" "${name_width}"
        printf '%s' "${gap}"
        print_table_cell "${VTI_INTERFACE}" "${interface_width}"
        printf '%s' "${gap}"
        print_table_cell "${VTI_NETWORK}" "${network_width}"
        printf '%s' "${gap}"
        print_table_cell "${management}" "${management_width}"
        printf '%s' "${gap}"

        case "${connection}" in
            CONNECTED)
                print_table_cell "${connection}" "${connection_width}" "${C_GREEN}${C_BOLD}" "${C_RESET}"
                ;;
            DISCONNECTED|"DISCONNECTED (DNS)"|BROKEN)
                print_table_cell "${connection}" "${connection_width}" "${C_RED}${C_BOLD}" "${C_RESET}"
                ;;
            *)
                print_table_cell "${connection}" "${connection_width}"
                ;;
        esac

        printf '%s' "${gap}"
        print_table_cell "${AUTH_ID}" "${auth_width}"
        printf '\n'

        ((index += 1))
    done < <(list_tunnel_names)

    if (( ${#dns_notices[@]} > 0 )); then
        echo
        local notice n_name n_status n_host n_dns n_vti n_detail
        for notice in "${dns_notices[@]}"; do
            IFS='|' read -r n_name n_status n_host n_dns n_vti n_detail <<< "${notice}"
            printf '%b\n' "${C_RED}${C_BOLD}[!] ${n_name}: Dynamic DNS endpoint requires attention${C_RESET}"
            printf '    Hostname:       %s\n' "${n_host}"
            case "${n_status}" in
                OUTDATED)
                    printf '    Current DNS IP: %s\n' "${n_dns}"
                    printf '    VTI remote IP:  %s\n' "${n_vti}"
                    printf '    Action:         Re-apply the tunnel to use the new DNS endpoint.\n'
                    ;;
                RESOLVE_FAILED|CHECK_UNAVAILABLE|MULTIPLE)
                    printf '    DNS status:     %s\n' "${n_detail}"
                    [[ -n "${n_vti}" ]] && printf '    VTI remote IP:  %s\n' "${n_vti}"
                    ;;
                VTI_MISSING)
                    printf '    Current DNS IP: %s\n' "${n_dns:-unknown}"
                    printf '    VTI status:     %s\n' "${n_detail}"
                    ;;
            esac
        done
    fi
}

select_tunnel() {
    local -a names=()
    local name selection i allow_all_networks="${1:-0}"

    while read -r name; do
        [[ -n "${name}" ]] && names+=("${name}")
    done < <(list_tunnel_names)

    (( ${#names[@]} > 0 )) || { warn "No tunnels configured."; return 1; }

    echo
    for i in "${!names[@]}"; do
        if load_tunnel "${names[$i]}"; then
            printf '  [%d] %s\n' "$((i + 1))" "${DISPLAY_NAME:-${NAME}}"
        else
            printf '  [%d] %s\n' "$((i + 1))" "${names[$i]}"
        fi
    done
    echo
    if [[ "${allow_all_networks}" == "all_networks" ]]; then
        echo "  [A] Show all tunnel networks"
        echo
    fi
    echo "Enter tunnel number and press ENTER."
    echo "B = Back    E = Exit"
    echo
    read -r -p "Selection: " selection

    case "${selection}" in
        ""|b|B|0) return 1 ;;
        e|E) clear_screen; echo "Bye."; exit 0 ;;
        a|A)
            [[ "${allow_all_networks}" == "all_networks" ]] || return 1
            SELECTED_TUNNEL="__ALL_NETWORKS__"
            return 0
            ;;
    esac

    [[ "${selection}" =~ ^[0-9]+$ ]] || return 1
    (( selection >= 1 && selection <= ${#names[@]} )) || return 1

    SELECTED_TUNNEL="${names[$((selection - 1))]}"
    return 0
}

# ==============================================================================
# Prompts
# ==============================================================================

valid_display_name() {
    local value="$1"
    (( ${#value} >= 1 && ${#value} <= 48 )) || return 1
    [[ "${value}" != *$'\n'* && "${value}" != *$'\r'* && "${value}" != *$'\t'* ]] || return 1
    [[ "${value}" != " "* && "${value}" != *" " ]] || return 1
}

display_name_in_use() {
    local wanted="$1"
    local ignore="${2:-}"
    local name

    DISPLAY_NAME_CONFLICT_TUNNEL=""
    while read -r name; do
        [[ -z "${name}" || "${name}" == "${ignore}" ]] && continue
        load_tunnel "${name}" || continue
        if [[ "${DISPLAY_NAME,,}" == "${wanted,,}" ]]; then
            DISPLAY_NAME_CONFLICT_TUNNEL="${NAME}"
            return 0
        fi
    done < <(list_tunnel_names)
    return 1
}

internal_name_artifacts_exist() {
    local name="$1"

    tunnel_exists "${name}" && return 0
    [[ -e "$(managed_swan_file "${name}")" ]] && return 0
    [[ -e "$(managed_vti_script "${name}")" ]] && return 0
    [[ -e "$(managed_service_file "${name}")" ]] && return 0
    [[ -L "${SYSTEMD_DIR}/multi-user.target.wants/$(managed_service_name "${name}")" ]] && return 0

    if command_available swanctl; then
        local conns
        conns="$(swanctl_clean swanctl --list-conns 2>/dev/null || true)"
        grep -qE "^${MANAGED_PREFIX}-${name}:" <<< "${conns}" && return 0
    fi
    return 1
}

display_to_internal_base() {
    local value="$1"
    local base

    base="${value,,}"
    base="${base// /-}"
    base="${base//./-}"
    base="$(printf '%s' "${base}" | tr -cd 'a-z0-9_-')"
    base="$(printf '%s' "${base}" | sed -E 's/[-_]+/-/g; s/^-+//; s/-+$//')"
    [[ -n "${base}" ]] || base="tunnel"
    [[ "${base}" =~ ^[a-z0-9] ]] || base="t-${base}"
    base="${base:0:32}"
    base="${base%-}"
    [[ -n "${base}" ]] || base="tunnel"
    printf '%s' "${base}"
}

next_internal_name_for_display() {
    local display="$1"
    local base candidate suffix n=1 max_base

    base="$(display_to_internal_base "${display}")"
    candidate="${base}"
    while internal_name_artifacts_exist "${candidate}"; do
        ((n += 1))
        suffix="-${n}"
        max_base=$((32 - ${#suffix}))
        candidate="${base:0:${max_base}}${suffix}"
    done
    printf '%s' "${candidate}"
}

prompt_display_name() {
    local suggested="$1"
    local ignore_internal="${2:-}"
    local value

    while :; do
        echo "This is the name shown in the S2S Manager interface."
        echo "It can be changed later without renaming strongSwan, systemd or manager files."
        echo
        echo "Rules:"
        echo "  • 1-48 characters"
        echo "  • spaces and normal display characters are allowed"
        echo "  • display names must be unique"
        echo
        read -r -p "Tunnel display name [${suggested}]: " value
        value="${value:-${suggested}}"

        if ! valid_display_name "${value}"; then
            validation_error_block \
                "INVALID DISPLAY NAME" \
                "Use 1-48 characters without leading/trailing spaces or control characters."
            continue
        fi

        if display_name_in_use "${value}" "${ignore_internal}"; then
            validation_error_block \
                "DISPLAY NAME ALREADY IN USE" \
                "Display name:  ${value}" \
                "Used by:      ${DISPLAY_NAME_CONFLICT_TUNNEL}"
            continue
        fi

        PROMPT_RESULT="${value}"
        return 0
    done
}

set_tunnel_display_name() {
    local name="$1"
    local new_display="$2"
    local file tmp

    file="$(tunnel_config_file "${name}")"
    [[ -f "${file}" ]] || return 1
    tmp="${file}.display-name.$$"

    awk '!/^DISPLAY_NAME=/' "${file}" > "${tmp}"
    printf 'DISPLAY_NAME=%q\n' "${new_display}" >> "${tmp}"
    chmod 600 "${tmp}"
    mv -f "${tmp}" "${file}"
}

peer_type_label() {
    case "${1:-unifi}" in
        debian) printf '%s' "Debian / strongSwan" ;;
        unifi)  printf '%s' "UniFi Gateway" ;;
        *)      printf '%s' "${1}" ;;
    esac
}

peer_vti_label() {
    case "${1:-unifi}" in
        debian) printf '%s' "Remote Debian VTI IP:" ;;
        *)      printf '%s' "UniFi VTI IP:" ;;
    esac
}

peer_endpoint_label() {
    case "${1:-unifi}" in
        debian) printf '%s' "Remote Debian public IP:" ;;
        *)      printf '%s' "Peer address:" ;;
    esac
}

prompt_tunnel_name() {
    local suggested="$1" value
    while :; do
        echo "The tunnel name is used locally by the S2S Manager."
        echo "Examples: home, office, backup"
        echo
        echo "Allowed:"
        echo "  • 1-32 characters"
        echo "  • letters, numbers, underscore (_) and hyphen (-)"
        echo "  • first character must be a letter or number"
        echo
        echo "Long names are allowed. Overview tables shorten long values for display only."
        echo "The complete tunnel name is always stored and used internally."
        echo
        echo "Press ENTER to accept the suggested value or enter another value."
        echo
        read -r -p "Tunnel name [${suggested}]: " value
        value="${value:-${suggested}}"

        if ! valid_tunnel_name "${value}"; then
            validation_error_block \
                "INVALID TUNNEL NAME" \
                "Entered:  ${value}" \
                "Allowed:  letters, numbers, underscore (_) and hyphen (-)" \
                "Length:   1-32 characters; first character must be alphanumeric" \
                "Spaces and dots are not allowed."
            continue
        fi

        if tunnel_exists "${value}"; then
            validation_error_block \
                "TUNNEL NAME ALREADY EXISTS" \
                "Entered:  ${value}" \
                "Source:   S2S Manager state"
            continue
        fi

        PROMPT_RESULT="${value}"
        return
    done
}

prompt_public_ip() {
    local suggested="$1"
    local peer_type="${2:-unifi}"
    local value

    while :; do
        echo "This is the public IPv4 address of THIS Debian server."
        echo "It is the local IPsec endpoint used by this S2S Manager."
        if [[ "${peer_type}" == "unifi" ]]; then
            echo "UniFi uses this address as its remote VPN gateway."
        else
            echo "The remote Debian peer uses this address as its remote IPsec endpoint."
        fi
        echo
        echo "Press ENTER to accept the suggested value or enter another value."
        echo
        read -r -p "Local Debian public IP [${suggested}]: " value
        value="${value:-${suggested}}"
        valid_ipv4 "${value}" || { error "Invalid IPv4 address."; echo; continue; }
        PROMPT_RESULT="${value}"
        return
    done
}

prompt_tunnel_network() {
    local suggested="$1"
    local peer_type="${2:-unifi}"
    local value normalized rc choice

    while :; do
        echo "Every Site-to-Site tunnel needs its own private /30 transfer network."
        echo
        echo "You may enter either:"
        echo "  10.200.201.0"
        echo "or"
        echo "  10.200.201.0/30"
        echo
        echo "Both formats are accepted."
        echo
        echo "The network must not overlap with LAN, VLAN, VPN, Teleport or other S2S networks."
        echo

        if (( $(tunnel_count) > 0 )); then
            echo "Existing S2S networks:"
            local n
            while read -r n; do
                [[ -z "${n}" ]] && continue
                load_tunnel "${n}" || continue
                printf '  • %s (%s)\n' "${VTI_NETWORK}" "${NAME}"
            done < <(list_tunnel_names)
            echo
        fi

        echo "Press ENTER to accept the suggested value or enter another network."
        echo
        read -r -p "Tunnel network [${suggested%%/*}]: " value
        value="${value:-${suggested}}"

        normalized="$(normalize_30_network "${value}")"
        rc=$?

        if (( rc == 1 )); then
            validation_error_block                 "INVALID TUNNEL NETWORK"                 "The entered value is not a valid IPv4 network:"                 "  ${value}"
            continue
        elif (( rc == 2 )); then
            validation_error_block                 "WRONG PREFIX LENGTH"                 "This manager uses /30 transfer networks."                 "Entered:    ${value}"                 "Suggested:  ${value%%/*}/30"
            echo
            echo "  [1] Use ${value%%/*}/30"
            echo "  [2] Enter another network"
            echo "  [B] Back"
            echo "  [E] Exit"
            echo
            read -r -p "Selection: " choice
            case "${choice}" in
                1) value="${value%%/*}/30"; normalized="$(normalize_30_network "${value}")" || continue ;;
                b|B|0) return 1 ;;
                e|E) clear_screen; echo "Bye."; exit 0 ;;
                *) continue ;;
            esac
        fi

        if ! network_is_exact_base "${value}"; then
            calculate_30_addresses "${normalized}"
            validation_error_block                 "HOST ADDRESS ENTERED"                 "${value%%/*} is not the base address of a /30 network."                 "Calculated network:  ${CALC_NETWORK}"                 "Local Debian IP:     ${CALC_DEBIAN}"                 "$([[ "${peer_type}" == "debian" ]] && echo "Remote Debian IP:    ${CALC_UNIFI}" || echo "UniFi IP:            ${CALC_UNIFI}")"                 "Broadcast:           ${CALC_BROADCAST}"
            echo
            confirm_yes_no "Use this calculated /30 network?" "N" || continue
        fi

        if check_network_conflict "${normalized}"; then
            show_network_conflict "${normalized}"
            echo
            continue
        fi

        calculate_30_addresses "${normalized}"

        validation_success "Tunnel network available: ${CALC_NETWORK}"
        printf '%-14s %s\n' "Network:" "${CALC_NETWORK}"
        printf '%-20s %s\n' "Local Debian IP:" "${CALC_DEBIAN}"
        if [[ "${peer_type}" == "debian" ]]; then
            printf '%-20s %s\n' "Remote Debian IP:" "${CALC_UNIFI}"
        else
            printf '%-20s %s\n' "UniFi IP:" "${CALC_UNIFI}"
        fi
        printf '%-14s %s\n' "Broadcast:" "${CALC_BROADCAST}"
        echo

        confirm_yes_no "Use these addresses?" "Y" || continue

        PROMPT_NETWORK="${CALC_NETWORK}"
        PROMPT_DEBIAN_IP="${CALC_DEBIAN}"
        PROMPT_UNIFI_IP="${CALC_UNIFI}"
        return
    done
}

valid_hostname() {
    local host="$1"

    (( ${#host} >= 1 && ${#host} <= 253 )) || return 1
    [[ "${host}" != *" "* ]] || return 1
    [[ "${host}" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || return 1
    [[ "${host}" != *".."* ]] || return 1

    local label
    IFS='.' read -r -a _host_labels <<< "${host}"
    for label in "${_host_labels[@]}"; do
        (( ${#label} >= 1 && ${#label} <= 63 )) || return 1
        [[ "${label}" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || return 1
    done
}

resolve_peer_hostname() {
    local host="$1"
    local -a ips=()

    command_available getent || return 2

    while IFS= read -r ip; do
        [[ -n "${ip}" ]] && ips+=("${ip}")
    done < <(getent ahostsv4 "${host}" 2>/dev/null | awk '{print $1}' | sort -u)

    if (( ${#ips[@]} == 0 )); then
        return 1
    fi

    if (( ${#ips[@]} > 1 )); then
        PEER_RESOLVE_MULTIPLE="${ips[*]}"
        return 3
    fi

    PEER_RESOLVED_IP="${ips[0]}"
    return 0
}

peer_mode_label() {
    case "$1" in
        dynamic) printf '%s' "Dynamic / unknown (wildcard VTI)" ;;
        static)  printf '%s' "Static IPv4" ;;
        dns)     printf '%s' "Hostname / Dynamic DNS" ;;
        *)       printf '%s' "$1" ;;
    esac
}

prompt_peer_endpoint() {
    local peer_type="${1:-unifi}"
    PROMPT_PEER_MODE=""
    PROMPT_PEER_ADDRESS=""

    if [[ "${peer_type}" == "debian" ]]; then
        echo "Choose how this Debian server identifies the remote Debian / strongSwan peer."
        echo
        echo "  [1] Static IPv4 address"
        echo "      Uses a peer-specific VTI endpoint."
        echo
        echo "  [2] Hostname / Dynamic DNS"
        echo "      strongSwan uses the hostname directly."
        echo "      The VTI resolves it to one IPv4 address when applied."
        echo "      Multiple DNS A records are rejected because one VTI has one endpoint."
        echo
        echo "  [B] Back"
        echo "  [E] Exit"
        echo
        echo "Press ENTER to use option 1."
    else
        echo "Choose how Debian identifies the public UniFi peer endpoint."
        echo
        echo "  [1] Dynamic / unknown"
        echo "      UniFi initiates the connection."
        echo "      Uses VTI remote 0.0.0.0."
        echo "      Only one wildcard VTI is possible per Debian public IP."
        echo
        echo "  [2] Static IPv4 address"
        echo "      Uses a peer-specific VTI."
        echo "      Allows additional VTI tunnels when peer endpoint IPs differ."
        echo
        echo "  [3] Hostname / Dynamic DNS"
        echo "      strongSwan uses the hostname directly."
        echo "      The VTI resolves it to one IPv4 address when applied."
        echo "      Multiple DNS A records are rejected because one VTI has one endpoint."
        echo
        echo "  [B] Back"
        echo "  [E] Exit"
        echo
        echo "Press ENTER to use option 1."
    fi

    local choice value rc static_choice dns_choice
    if [[ "${peer_type}" == "debian" ]]; then
        static_choice=1; dns_choice=2
    else
        static_choice=2; dns_choice=3
    fi

    while :; do
        read -r -p "Selection [1]: " choice
        choice="${choice:-1}"

        if [[ "${peer_type}" != "debian" && "${choice}" == "1" ]]; then
            PROMPT_PEER_MODE="dynamic"
            PROMPT_PEER_ADDRESS=""
            return 0
        elif [[ "${choice}" == "${static_choice}" ]]; then
            echo
            while :; do
                if [[ "${peer_type}" == "debian" ]]; then
                    read -r -p "Remote Debian public IPv4: " value
                else
                    read -r -p "UniFi public IPv4: " value
                fi
                [[ -z "${value}" ]] && { warn "IPv4 address is required."; continue; }
                if ! valid_ipv4 "${value}" || [[ "${value}" == "0.0.0.0" ]]; then
                    validation_error_block "INVALID PEER IPV4" "Entered:  ${value}" "Enter a valid public IPv4 address for the remote peer."
                    continue
                fi
                PROMPT_PEER_MODE="static"
                PROMPT_PEER_ADDRESS="${value}"
                return 0
            done
        elif [[ "${choice}" == "${dns_choice}" ]]; then
            echo
            while :; do
                echo "Enter only the hostname / FQDN."
                echo "Do NOT include http://, https://, a port or a path."
                echo "Example: peer.example.com"
                echo
                echo "Hostname only - this is NOT a web URL."
                if [[ "${peer_type}" == "debian" ]]; then
                    read -r -p "Remote Debian hostname / Dynamic DNS name: " value
                else
                    read -r -p "UniFi hostname / Dynamic DNS name: " value
                fi
                [[ -z "${value}" ]] && { warn "Hostname is required."; continue; }
                if [[ "${value}" == *"://"* || "${value}" == */* || "${value}" == *:* ]]; then
                    validation_error_block "HOSTNAME ONLY - NOT A URL" "Entered:  ${value}" "Use only the hostname / FQDN." "Example:  peer.example.com" "Do not include http://, https://, ports or paths."
                    continue
                fi
                if ! valid_hostname "${value}"; then
                    validation_error_block "INVALID PEER HOSTNAME" "Entered:  ${value}" "Use a valid hostname such as peer.example.com."
                    continue
                fi
                PEER_RESOLVED_IP=""; PEER_RESOLVE_MULTIPLE=""
                resolve_peer_hostname "${value}"; rc=$?
                case "${rc}" in
                    0) validation_success "Hostname currently resolves to ${PEER_RESOLVED_IP}" ;;
                    1) warn "Hostname is valid but currently does not resolve to IPv4."; echo "The definition may still be saved, but installation will be blocked until it resolves." ;;
                    2) warn "getent is unavailable, so DNS cannot currently be checked." ;;
                    3) validation_error_block "MULTIPLE IPV4 ADDRESSES" "Hostname:  ${value}" "IPv4s:     ${PEER_RESOLVE_MULTIPLE}" "A classic VTI requires one concrete remote endpoint."; continue ;;
                esac
                PROMPT_PEER_MODE="dns"
                PROMPT_PEER_ADDRESS="${value}"
                return 0
            done
        else
            case "${choice}" in
                b|B|0) return 1 ;;
                e|E) clear_screen; echo "Bye."; exit 0 ;;
                *) if [[ "${peer_type}" == "debian" ]]; then validation_error_block "INVALID SELECTION" "Choose 1 or 2."; else validation_error_block "INVALID SELECTION" "Choose 1, 2 or 3."; fi ;;
            esac
        fi
    done
}

prompt_auth_id() {
    local suggested="$1" value
    while :; do
        echo "The UniFi gateway identifies itself to Debian using this IKE identity."
        echo "This is not an IP address and does not need to resolve in DNS."
        echo "Use a unique Authentication ID for every S2S tunnel."
        echo
        echo "Allowed:"
        echo "  • 1-64 characters"
        echo "  • letters, numbers, dot (.), underscore (_), colon (:) and hyphen (-)"
        echo "  • first character must be a letter or number"
        echo
        echo "Press ENTER to accept the suggested value or enter another value."
        echo
        read -r -p "UniFi authentication ID [${suggested}]: " value
        value="${value:-${suggested}}"

        if ! valid_auth_id "${value}"; then
            validation_error_block \
                "INVALID AUTHENTICATION ID" \
                "Entered:  ${value}" \
                "Allowed:  letters, numbers, dot (.), underscore (_), colon (:) and hyphen (-)" \
                "Length:   1-64 characters; first character must be alphanumeric" \
                "Spaces are not allowed."
            continue
        fi

        if auth_id_in_use "${value}"; then
            validation_error_block \
                "AUTHENTICATION ID ALREADY IN USE" \
                "Entered:  ${value}" \
                "Source:   S2S Manager state"
            continue
        fi

        if auth_id_in_loaded_swan "${value}"; then
            validation_error_block \
                "AUTHENTICATION ID ALREADY IN USE" \
                "Entered:  ${value}" \
                "Source:   loaded strongSwan connection"
            continue
        fi

        PROMPT_RESULT="${value}"
        return
    done
}

prompt_remote_networks() {
    local own_tunnel_network="${1:-}"
    local peer_type="${2:-unifi}"

    PROMPT_ROUTES=()
    if [[ "${peer_type}" == "debian" ]]; then
        echo "Enter networks behind the remote Debian peer that this server must reach through the S2S tunnel."
        echo
        echo "Examples:"
        echo "  10.50.0.0/24       Remote server-side network"
        echo "  172.20.0.0/16      Remote routed network"
    else
        echo "Enter UniFi-side networks that Debian must return through the S2S tunnel."
        echo
        echo "Examples:"
        echo "  192.168.178.0/23   Main LAN"
        echo "  192.168.4.0/24     UniFi Teleport"
    fi
    echo
    echo "Networks are checked for overlaps with tunnel networks,"
    echo "other remote networks and live Debian routes (LAN/VPN/WireGuard/etc.)."
    echo
    echo "Enter one network per line."
    echo "Press ENTER on an empty line when finished."
    echo

    local index=1 route normalized existing conflict
    while :; do
        read -r -p "Remote network #${index}: " route

        if [[ -z "${route}" ]]; then
            if (( ${#PROMPT_ROUTES[@]} == 0 )); then
                info "Remote network entry finished: no remote networks configured."
            else
                validation_success "Remote network entry finished (${#PROMPT_ROUTES[@]} network(s))."
            fi
            return 0
        fi

        if ! valid_cidr "${route}"; then
            validation_error_block \
                "INVALID CIDR NETWORK" \
                "The entered value is not a valid IPv4 CIDR network:" \
                "  ${route}"
            continue
        fi

        if [[ "${route}" == "0.0.0.0/0" ]]; then
            validation_error_block \
                "REMOTE NETWORK NOT ALLOWED" \
                "0.0.0.0/0 is not allowed as a remote network." \
                "Use explicit remote LAN/VLAN networks instead."
            continue
        fi

        if ! cidr_is_exact_network "${route}"; then
            normalized="$(cidr_normalized "${route}")"
            validation_error_block \
                "HOST ADDRESS ENTERED" \
                "${route} is not the network base address." \
                "Use instead:  ${normalized}"
            continue
        fi
        normalized="$(cidr_normalized "${route}")"

        if [[ -n "${own_tunnel_network}" ]] &&
           cidr_overlaps "${normalized}" "${own_tunnel_network}"; then
            validation_error_block \
                "NETWORK CONFLICT" \
                "Remote network:  ${normalized}" \
                "Tunnel network:  ${own_tunnel_network}" \
                "Reason:          remote network overlaps this tunnel's transfer network"
            continue
        fi

        conflict=0
        for existing in "${PROMPT_ROUTES[@]:-}"; do
            [[ -z "${existing}" ]] && continue
            if cidr_overlaps "${normalized}" "${existing}"; then
                validation_error_block \
                    "NETWORK CONFLICT" \
                    "Requested:       ${normalized}" \
                    "Conflicts with:  ${existing}" \
                    "Reason:          overlaps another remote network entered for this tunnel"
                conflict=1
                break
            fi
        done
        (( conflict == 1 )) && continue

        if check_network_conflict "${normalized}"; then
            show_network_conflict "${normalized}"
            continue
        fi

        validation_success "Network available: ${normalized}"
        PROMPT_ROUTES+=("${normalized}")
        ((index += 1))
    done
}

prompt_psk() {
    local peer_type="${1:-unifi}"
    local choice value
    if [[ "${peer_type}" == "debian" ]]; then
        echo "The same Pre-Shared Key will be included in the Debian peer bundle."
        echo "The bundle is sensitive and should only be transferred securely."
    else
        echo "The same Pre-Shared Key must later be entered in UniFi."
    fi
    echo
    echo "  [1] Generate a secure random PSK"
    echo "  [2] Enter my own PSK"
    echo "  [B] Back"
    echo "  [E] Exit"
    echo
    echo "Press ENTER to use option 1."
    echo

    while :; do
        read -r -p "Selection [1]: " choice
        choice="${choice:-1}"
        case "${choice}" in
            1)
                PROMPT_PSK="$(generate_psk)"
                ok "Secure random PSK generated."
                return
                ;;
            2)
                read -r -s -p "Pre-Shared Key: " value
                echo
                [[ -n "${value}" ]] || { error "PSK must not be empty."; continue; }
                PROMPT_PSK="${value}"
                return
                ;;
            b|B|0) return 1 ;;
            e|E) clear_screen; echo "Bye."; exit 0 ;;
            *) error "Invalid selection." ;;
        esac
    done
}

# ==============================================================================
# Firewall management
# ==============================================================================

ufw_rule_allows_port() {
    local port="$1"
    local proto="$2"
    local rules

    valid_port "${port}" || return 1
    [[ "${proto}" == "tcp" || "${proto}" == "udp" ]] || return 1
    ufw_installed || return 1

    rules="$({ ufw status 2>/dev/null || true; ufw show added 2>/dev/null || true; })"
    grep -Eiq "(^|[[:space:]])${port}(/${proto}|[[:space:]].*${proto})([[:space:]]|$).*ALLOW|ufw[[:space:]]+allow[[:space:]]+${port}/${proto}([[:space:]]|$)" <<< "${rules}"
}

ufw_allow_rule_spec_exists() {
    local port="$1" proto="$2" source="$3"
    local status added

    valid_port "${port}" || return 1
    [[ "${proto}" == "tcp" || "${proto}" == "udp" ]] || return 1
    ufw_installed || return 1

    status="$(ufw status 2>/dev/null || true)"
    added="$(ufw show added 2>/dev/null || true)"

    if [[ "${source}" == "any" ]]; then
        grep -Eq "(^|[[:space:]])${port}/${proto}([[:space:]]|$).*ALLOW.*Anywhere" <<< "${status}" && return 0
        grep -Eq "(^|[[:space:]])ufw[[:space:]]+allow([[:space:]]+in)?[[:space:]]+${port}/${proto}([[:space:]]|$)" <<< "${added}" && return 0
    else
        grep -F "${port}/${proto}" <<< "${status}" | grep -Fq "${source}" && return 0
        grep -F "allow from ${source} to any port ${port} proto ${proto}" <<< "${added}" >/dev/null && return 0
    fi

    return 1
}

valid_ufw_rule_description() {
    local value="$1"
    local pattern='^[A-Za-z0-9ÄÖÜäöüß][A-Za-z0-9ÄÖÜäöüß._: -]*$'
    [[ -n "${value}" && ${#value} -le 48 ]] || return 1
    [[ "${value}" =~ ${pattern} ]]
}

ufw_temp_state_file() {
    printf '%s/%s.rule' "${UFW_TEMP_DIR}" "$1"
}

ufw_temp_service_name() {
    printf '%s-%s.service' "${UFW_TIMER_PREFIX}" "$1"
}

ufw_temp_timer_name() {
    printf '%s-%s.timer' "${UFW_TIMER_PREFIX}" "$1"
}

load_ufw_temp_rule() {
    local id="$1"
    local state_file
    state_file="$(ufw_temp_state_file "${id}")"
    [[ -f "${state_file}" ]] || return 1

    unset UFW_TEMP_ID UFW_TEMP_PORT UFW_TEMP_PROTO UFW_TEMP_SOURCE
    unset UFW_TEMP_DESCRIPTION UFW_TEMP_COMMENT UFW_TEMP_CREATED UFW_TEMP_EXPIRES
    # Manager-created state only.
    # shellcheck disable=SC1090
    source "${state_file}"

    [[ "${UFW_TEMP_ID:-}" == "${id}" ]] || return 1
    valid_port "${UFW_TEMP_PORT:-}" || return 1
    [[ "${UFW_TEMP_PROTO:-}" == "tcp" || "${UFW_TEMP_PROTO:-}" == "udp" ]] || return 1
    [[ "${UFW_TEMP_SOURCE:-}" == "any" ]] || valid_ipv4 "${UFW_TEMP_SOURCE:-}" || valid_cidr "${UFW_TEMP_SOURCE:-}" || return 1
    [[ "${UFW_TEMP_EXPIRES:-}" =~ ^[0-9]+$ ]] || return 1
}

save_ufw_temp_rule() {
    local id="$1" port="$2" proto="$3" source="$4" description="$5"
    local comment="$6" created="$7" expires="$8"
    local state_file
    state_file="$(ufw_temp_state_file "${id}")"

    mkdir -p "${UFW_TEMP_DIR}"
    {
        printf 'UFW_TEMP_ID=%q\n' "${id}"
        printf 'UFW_TEMP_PORT=%q\n' "${port}"
        printf 'UFW_TEMP_PROTO=%q\n' "${proto}"
        printf 'UFW_TEMP_SOURCE=%q\n' "${source}"
        printf 'UFW_TEMP_DESCRIPTION=%q\n' "${description}"
        printf 'UFW_TEMP_COMMENT=%q\n' "${comment}"
        printf 'UFW_TEMP_CREATED=%q\n' "${created}"
        printf 'UFW_TEMP_EXPIRES=%q\n' "${expires}"
    } > "${state_file}"
    chmod 600 "${state_file}"
}

build_ufw_rule_args() {
    local port="$1" proto="$2" source="$3"
    UFW_RULE_ARGS=(allow)
    if [[ "${source}" == "any" ]]; then
        UFW_RULE_ARGS+=("${port}/${proto}")
    else
        UFW_RULE_ARGS+=(from "${source}" to any port "${port}" proto "${proto}")
    fi
}

ufw_temp_rule_comment_exists() {
    local comment="$1"
    local rules
    ufw_installed || return 1
    rules="$({ ufw status 2>/dev/null || true; ufw show added 2>/dev/null || true; })"
    grep -Fq "${comment}" <<< "${rules}"
}

remove_ufw_temp_timer_files() {
    local id="$1"
    local service timer
    service="$(ufw_temp_service_name "${id}")"
    timer="$(ufw_temp_timer_name "${id}")"

    systemctl disable --now "${timer}" >/dev/null 2>&1 || true
    rm -f -- "${SYSTEMD_DIR}/${service}" "${SYSTEMD_DIR}/${timer}"
    rm -f -- "$(ufw_temp_state_file "${id}")"
    systemctl daemon-reload >/dev/null 2>&1 || true
}

reconcile_ufw_temp_rules() {
    local state_file id now changed=0
    now="$(date +%s)"

    shopt -s nullglob
    for state_file in "${UFW_TEMP_DIR}"/*.rule; do
        id="$(basename "${state_file}" .rule)"
        if ! load_ufw_temp_rule "${id}"; then
            warn "Invalid temporary UFW state: ${state_file}"
            continue
        fi
        if (( UFW_TEMP_EXPIRES <= now )) && ! ufw_temp_rule_comment_exists "${UFW_TEMP_COMMENT}"; then
            remove_ufw_temp_timer_files "${id}"
            changed=1
        fi
    done
    shopt -u nullglob

    return $(( changed == 1 ? 0 : 1 ))
}

schedule_ufw_temp_rule() {
    local id="$1" port="$2" proto="$3" source="$4" description="$5"
    local comment="$6" expires="$7"
    local service timer ufw_path calendar exec_line

    service="$(ufw_temp_service_name "${id}")"
    timer="$(ufw_temp_timer_name "${id}")"
    ufw_path="$(command -v ufw)"
    [[ "${ufw_path}" == /* ]] || return 1
    calendar="$(date -u -d "@${expires}" '+%Y-%m-%d %H:%M:%S UTC')" || return 1

    if [[ "${source}" == "any" ]]; then
        exec_line="${ufw_path} --force delete allow ${port}/${proto} comment \"${comment}\""
    else
        exec_line="${ufw_path} --force delete allow from ${source} to any port ${port} proto ${proto} comment \"${comment}\""
    fi

    cat > "${SYSTEMD_DIR}/${service}" <<EOF
[Unit]
Description=Expire temporary UFW rule ${id}

[Service]
Type=oneshot
ExecStart=${exec_line}
EOF

    cat > "${SYSTEMD_DIR}/${timer}" <<EOF
[Unit]
Description=Expiry timer for temporary UFW rule ${id}

[Timer]
OnCalendar=${calendar}
Persistent=true
AccuracySec=1s
Unit=${service}

[Install]
WantedBy=timers.target
EOF

    chmod 644 "${SYSTEMD_DIR}/${service}" "${SYSTEMD_DIR}/${timer}"
    systemctl daemon-reload || return 1
    systemctl enable --now "${timer}" || return 1
}

format_ufw_expiry() {
    local epoch="$1"
    date -d "@${epoch}" '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null || printf 'epoch %s' "${epoch}"
}

sanitize_ufw_rule_display() {
    sed -E \
        -e 's/S2S Manager TEMP [A-Za-z0-9_-]+ //' \
        -e 's/S2S Manager PERM //'
}

print_annotated_ufw_rules() {
    local line display_line id label expires now is_temporary
    now="$(date +%s)"

    while IFS= read -r line; do
        if [[ "${line}" =~ ^\[[[:space:]]*[0-9]+\] ]]; then
            is_temporary=0
            if [[ "${line}" =~ S2S[[:space:]]Manager[[:space:]]TEMP[[:space:]]([A-Za-z0-9_-]+) ]]; then
                is_temporary=1
                id="${BASH_REMATCH[1]}"
                if load_ufw_temp_rule "${id}"; then
                    expires="$(format_ufw_expiry "${UFW_TEMP_EXPIRES}")"
                    if (( UFW_TEMP_EXPIRES <= now )); then
                        label="[TEMP EXPIRED - cleanup pending: ${expires}]"
                    else
                        label="[TEMP until ${expires}]"
                    fi
                else
                    label="[TEMP - state missing]"
                fi
            fi
            display_line="$(sanitize_ufw_rule_display <<< "${line}")"
            if (( is_temporary )); then
                printf '%b%s  %s%b\n' "${C_YELLOW}${C_BOLD}" "${display_line}" "${label}" "${C_RESET}"
            else
                printf '%s\n' "${display_line}"
            fi
        else
            printf '%s\n' "${line}"
        fi
    done < <(ufw status numbered 2>/dev/null || true)
}

print_annotated_ufw_added_rules() {
    local line display_line id label expires now is_temporary count=0
    local port proto source comment suffix
    now="$(date +%s)"

    printf '%-28s %-12s %-28s %s\n' "To" "Action" "From" "Description / lifetime"
    printf '%-28s %-12s %-28s %s\n' "--" "------" "----" "----------------------"

    while IFS= read -r line; do
        if [[ "${line}" == ufw\ * ]]; then
            count=$((count + 1))
            is_temporary=0
            label=""
            if [[ "${line}" =~ S2S[[:space:]]Manager[[:space:]]TEMP[[:space:]]([A-Za-z0-9_-]+) ]]; then
                is_temporary=1
                id="${BASH_REMATCH[1]}"
                if load_ufw_temp_rule "${id}"; then
                    expires="$(format_ufw_expiry "${UFW_TEMP_EXPIRES}")"
                    if (( UFW_TEMP_EXPIRES <= now )); then
                        label="[TEMP EXPIRED - cleanup pending: ${expires}]"
                    else
                        label="[TEMP until ${expires}]"
                    fi
                else
                    label="[TEMP - state missing]"
                fi
            fi
            display_line="$(sanitize_ufw_rule_display <<< "${line}")"

            comment=""
            if [[ "${display_line}" == *" comment "* ]]; then
                comment="${display_line#* comment }"
                comment="${comment#\'}"
                comment="${comment%\'}"
                display_line="${display_line%% comment *}"
            fi
            suffix=""
            [[ -n "${comment}" ]] && suffix="# ${comment}"
            [[ -n "${label}" ]] && suffix="${suffix}${suffix:+  }${label}"

            port=""; proto=""; source=""
            if [[ "${display_line}" =~ ^ufw[[:space:]]+allow([[:space:]]+in)?[[:space:]]+([0-9]+)/(tcp|udp)([[:space:]]|$) ]]; then
                port="${BASH_REMATCH[2]}"
                proto="${BASH_REMATCH[3]}"
                source="Anywhere"
            elif [[ "${display_line}" =~ ^ufw[[:space:]]+allow([[:space:]]+in)?[[:space:]]+from[[:space:]]+([^[:space:]]+)[[:space:]]+to[[:space:]]+any[[:space:]]+port[[:space:]]+([0-9]+)[[:space:]]+proto[[:space:]]+(tcp|udp)([[:space:]]|$) ]]; then
                source="${BASH_REMATCH[2]}"
                port="${BASH_REMATCH[3]}"
                proto="${BASH_REMATCH[4]}"
                [[ "${source}" == "any" ]] && source="Anywhere"
            fi

            if [[ -n "${port}" ]]; then
                if (( is_temporary )); then
                    printf '%b%-28s %-12s %-28s %s%b\n' "${C_YELLOW}${C_BOLD}" \
                        "${port}/${proto}" "ALLOW IN" "${source}" "${suffix}" "${C_RESET}"
                else
                    printf '%-28s %-12s %-28s %s\n' "${port}/${proto}" "ALLOW IN" "${source}" "${suffix}"
                fi
            else
                printf '%-28s %-12s %-28s %s\n' "(complex rule)" "STORED" "see command" "${suffix}"
                printf '    %s\n' "$(sanitize_ufw_rule_display <<< "${line}")"
            fi
        fi
    done < <(ufw show added 2>/dev/null || true)

    (( count > 0 )) || info "No stored UFW rules were found."
}

show_all_ufw_rules() {
    banner
    section "UFW FIREWALL RULES"

    if ! ufw_installed; then
        info "UFW is not installed."
        pause
        return
    fi

    reconcile_ufw_temp_rules >/dev/null 2>&1 || true

    echo "Firewall status and default policies:"
    echo
    # `ufw status verbose` also prints the full rule table. Stop before that
    # table because the same rules are shown once, with numbers, below.
    ufw status verbose 2>&1 | awk '
        /^To[[:space:]]+Action[[:space:]]+From/ { exit }
        { print }
    ' || true

    echo
    section "NUMBERED RULES"
    if ufw_active; then
        print_annotated_ufw_rules
    else
        info "UFW is inactive, so UFW does not provide numbered live rules."
    fi

    if ! ufw_active; then
        echo
        section "CONFIGURED RULES (UFW INACTIVE)"
        info "UFW is inactive. These stored rules would apply after enabling it."
        echo
        print_annotated_ufw_added_rules
    fi

    pause
}

prompt_ufw_rule_details() {
    local protocol port source description normalized

    banner
    section "ADD FIREWALL RULE"
    echo "Create one incoming ALLOW rule in four guided steps."

    section "STEP 1/4 - PROTOCOL"
    cat <<'EOF'
Choose the transport protocol used by the service:

  tcp  connection-oriented services such as SSH, HTTP, HTTPS, MQTT or FRP
  udp  datagram services such as WireGuard, DNS or many game/voice services

HTTP and HTTPS are application protocols. For a normal web server choose TCP
here. Enter only tcp or udp, not http, https, :// or a URL.

B = cancel this wizard and return to UFW management
E = exit the program
EOF

    while :; do
        echo
        read -r -p "Protocol [tcp]: " protocol
        case "${protocol}" in
            b|B) info "Firewall rule wizard cancelled."; return 1 ;;
            e|E) clear_screen; echo "Bye."; exit 0 ;;
        esac
        protocol="${protocol:-tcp}"
        protocol="$(tr '[:upper:]' '[:lower:]' <<< "${protocol}")"
        if [[ "${protocol}" == "tcp" || "${protocol}" == "udp" ]]; then
            break
        fi
        error "Protocol must be tcp or udp. Do not enter http, https or :// here."
    done

    section "STEP 2/4 - DESTINATION PORT"
    cat <<'EOF'
Enter one numeric destination port from 1 through 65535.

Common examples:
  22     SSH
  80     HTTP
  443    HTTPS
  1883   MQTT
  51820  WireGuard (normally UDP)

Enter only the number. Do not enter tcp/443, https://, :443 or a port range.

B = cancel this wizard and return to UFW management
E = exit the program
EOF

    while :; do
        echo
        read -r -p "Destination port (1-65535): " port
        case "${port}" in
            b|B) info "Firewall rule wizard cancelled."; return 1 ;;
            e|E) clear_screen; echo "Bye."; exit 0 ;;
        esac
        if valid_port "${port}"; then
            port=$((10#${port}))
            break
        fi
        error "Enter only one numeric port from 1 through 65535."
        echo "Examples: 22 for SSH, 80 for HTTP, 443 for HTTPS, 51820 for WireGuard."
    done

    section "STEP 3/4 - ALLOWED SOURCE"
    cat <<'EOF'
Choose which remote addresses may connect to this local destination port:

  any                    every IPv4/IPv6 source when externally reachable
  198.51.100.25          one IPv4 address only
  192.168.10.0/24        one IPv4 CIDR network

This field accepts only "any", a plain IPv4 address or an IPv4 CIDR network.
Do not enter http://, https://, a hostname, URL path, protocol or appended port.

Invalid examples: https://example.com, server.example.com, 1.2.3.4:22

B = cancel this wizard and return to UFW management
E = exit the program
EOF

    while :; do
        echo
        read -r -p "Allowed source [any]: " source
        case "${source}" in
            b|B) info "Firewall rule wizard cancelled."; return 1 ;;
            e|E) clear_screen; echo "Bye."; exit 0 ;;
        esac
        source="${source:-any}"
        source="$(tr '[:upper:]' '[:lower:]' <<< "${source}")"
        if [[ "${source}" == "any" ]] || valid_ipv4 "${source}"; then
            break
        fi
        if valid_cidr "${source}"; then
            normalized="$(cidr_normalized "${source}")"
            if [[ "${source}" != "${normalized}" ]]; then
                info "Network normalized to ${normalized}."
                source="${normalized}"
            fi
            break
        fi
        error "Source must be 'any', one plain IPv4 address or one IPv4 CIDR network."
        echo "Do not include http://, https://, a hostname, path, protocol or port."
    done

    section "STEP 4/4 - DESCRIPTION"
    cat <<'EOF'
Enter a short label explaining why the rule exists.

Examples:
  HTTPS web server
  MQTT from home network
  Temporary admin access

The description is stored as the UFW rule comment. Do not enter a command,
URL or secret. Allowed length: 1-48 characters.

B = cancel this wizard and return to UFW management
E = exit the program
EOF

    while :; do
        echo
        read -r -p "Rule description (1-48 characters): " description
        case "${description}" in
            b|B) info "Firewall rule wizard cancelled."; return 1 ;;
            e|E) clear_screen; echo "Bye."; exit 0 ;;
        esac
        if valid_ufw_rule_description "${description}"; then
            break
        fi
        error "Use 1-48 letters, numbers, spaces, dots, underscores, colons or hyphens."
    done

    PROMPT_UFW_PROTOCOL="${protocol}"
    PROMPT_UFW_PORT="${port}"
    PROMPT_UFW_SOURCE="${source}"
    PROMPT_UFW_DESCRIPTION="${description}"
}

prompt_ufw_temp_duration() {
    local choice minutes

    banner
    section "TEMPORARY RULE DURATION"
    cat <<'EOF'
The rule is stored in UFW and marked as temporary. A persistent systemd timer
removes it at the selected time. The timer survives a server restart.

This is different from a direct iptables/nftables runtime rule, which UFW may
not display and which can disappear during reload or reboot.
EOF
    echo
    echo "  [1] 15 minutes"
    echo "  [2] 1 hour"
    echo "  [3] 8 hours"
    echo "  [4] 24 hours"
    echo "  [5] Enter minutes (1-10080 / up to 7 days)"
    echo "  [B] Back"
    echo "  [E] Exit"
    echo
    read -r -p "Selection: " choice

    case "${choice}" in
        1) minutes=15 ;;
        2) minutes=60 ;;
        3) minutes=480 ;;
        4) minutes=1440 ;;
        5)
            read -r -p "Duration in minutes (1-10080): " minutes
            if ! [[ "${minutes}" =~ ^[0-9]+$ ]] || (( minutes < 1 || minutes > 10080 )); then
                error "Duration must be between 1 and 10080 minutes."
                pause
                return 1
            fi
            ;;
        b|B|0) return 1 ;;
        e|E) clear_screen; echo "Bye."; exit 0 ;;
        *) error "Invalid selection."; pause; return 1 ;;
    esac

    PROMPT_UFW_DURATION_MINUTES="${minutes}"
}

add_ufw_rule() {
    local lifetime="$1"
    local comment choice output created expires id expiry_text

    ufw_installed || { error "UFW is not installed."; pause; return 1; }
    prompt_ufw_rule_details || return

    if [[ "${lifetime}" == "temporary" ]]; then
        prompt_ufw_temp_duration || return
        created="$(date +%s)"
        expires=$(( created + PROMPT_UFW_DURATION_MINUTES * 60 ))
        id="${created}-${RANDOM}"
        comment="S2S Manager TEMP ${id} ${PROMPT_UFW_DESCRIPTION}"
        expiry_text="$(format_ufw_expiry "${expires}")"
    else
        comment="S2S Manager PERM ${PROMPT_UFW_DESCRIPTION}"
        expiry_text="never"
    fi

    banner
    section "FIREWALL RULE PREVIEW"
    printf '%-24s %s\n' "Action:" "ALLOW IN"
    printf '%-24s %s\n' "Protocol:" "${PROMPT_UFW_PROTOCOL^^}"
    printf '%-24s %s\n' "Destination port:" "${PROMPT_UFW_PORT}"
    printf '%-24s %s\n' "Allowed source:" "${PROMPT_UFW_SOURCE}"
    printf '%-24s %s\n' "Description:" "${PROMPT_UFW_DESCRIPTION}"
    printf '%-24s %s\n' "Lifetime:" "${lifetime^^}"
    [[ "${lifetime}" == "temporary" ]] && printf '%-24s %s\n' "Expires:" "${expiry_text}"
    echo
    warn "An ALLOW rule opens the selected port to the displayed source."
    [[ "${PROMPT_UFW_SOURCE}" == "any" ]] && warn "Source 'any' allows connections from the Internet when externally reachable."
    echo
    read -r -p "Create this firewall rule? [y/N]: " choice
    [[ "${choice,,}" == "y" ]] || { info "No rule was created."; pause; return 0; }

    if ufw_allow_rule_spec_exists "${PROMPT_UFW_PORT}" "${PROMPT_UFW_PROTOCOL}" "${PROMPT_UFW_SOURCE}"; then
        error "An equivalent ALLOW rule already exists."
        echo "The manager will not change its comment or lifetime classification."
        echo "Delete or review the existing rule before creating a replacement."
        pause
        return 1
    fi

    build_ufw_rule_args "${PROMPT_UFW_PORT}" "${PROMPT_UFW_PROTOCOL}" "${PROMPT_UFW_SOURCE}"
    if ! output="$(ufw "${UFW_RULE_ARGS[@]}" comment "${comment}" 2>&1)"; then
        error "UFW could not create the rule."
        [[ -n "${output}" ]] && printf '%s\n' "${output}"
        pause
        return 1
    fi

    if [[ "${lifetime}" == "temporary" ]]; then
        save_ufw_temp_rule "${id}" "${PROMPT_UFW_PORT}" "${PROMPT_UFW_PROTOCOL}" \
            "${PROMPT_UFW_SOURCE}" "${PROMPT_UFW_DESCRIPTION}" "${comment}" "${created}" "${expires}"
        if ! schedule_ufw_temp_rule "${id}" "${PROMPT_UFW_PORT}" "${PROMPT_UFW_PROTOCOL}" \
            "${PROMPT_UFW_SOURCE}" "${PROMPT_UFW_DESCRIPTION}" "${comment}" "${expires}"; then
            error "The expiry timer could not be created. Rolling back the UFW rule."
            ufw --force delete "${UFW_RULE_ARGS[@]}" comment "${comment}" >/dev/null 2>&1 || true
            remove_ufw_temp_timer_files "${id}"
            pause
            return 1
        fi
        ok "Temporary UFW rule created."
        ok "Automatic removal scheduled for ${expiry_text}."
    else
        ok "Permanent UFW rule created."
    fi
    pause
}

delete_ufw_rule() {
    local choice rules number selected ssh_port id confirm

    banner
    section "DELETE UFW RULE"
    if ! ufw_installed; then
        info "UFW is not installed."
        pause
        return
    fi
    if ! ufw_active; then
        warn "UFW is inactive and does not expose numbered live rules."
        info "Deletion by number is therefore unavailable in this first implementation."
        echo "Stored rules remain visible through 'Show all firewall rules'."
        pause
        return
    fi

    print_annotated_ufw_rules
    echo
    echo "Enter the number shown in square brackets. Enter B to go back."
    read -r -p "Rule number: " choice
    [[ "${choice}" =~ ^[0-9]+$ ]] || { [[ "${choice}" =~ ^[Bb]$ ]] && return; error "Enter a numeric rule number."; pause; return 1; }
    number=$((10#${choice}))
    rules="$(ufw status numbered 2>/dev/null || true)"
    selected="$(awk -v wanted="${number}" '
        /^\[[[:space:]]*[0-9]+\]/ {
            n=$0
            sub(/^\[[[:space:]]*/, "", n)
            sub(/\].*$/, "", n)
            if ((n+0) == wanted) { print; exit }
        }
    ' <<< "${rules}")"
    if [[ -z "${selected}" ]]; then
        error "Rule number ${number} does not exist."
        pause
        return 1
    fi

    banner
    section "DELETE RULE PREVIEW"
    printf '%s\n' "${selected}"
    echo

    ssh_port="$(detect_ssh_port)"
    if grep -Eq "(^|[[:space:]])${ssh_port}/tcp([[:space:]]|$)" <<< "${selected}" || \
       grep -Fq "S2S Manager SSH safety" <<< "${selected}" || \
       grep -Eiq 'OpenSSH|#[[:space:]].*SSH' <<< "${selected}"; then
        error "This rule protects the detected SSH administration port TCP ${ssh_port}."
        error "The manager refuses to delete it because the current remote session could be locked out."
        pause
        return 1
    fi

    if grep -Eq 'S2S Manager (WireGuard|IKE|NAT-T)|500/udp|4500/udp|/esp' <<< "${selected}"; then
        warn "This appears to be a VPN/IPsec rule. Deleting it may disconnect a tunnel or client."
    else
        warn "Deleting an allow rule can immediately make the service unreachable."
    fi
    echo
    read -r -p "Type DELETE to remove this rule: " confirm
    [[ "${confirm}" == "DELETE" ]] || { info "Rule was not deleted."; pause; return 0; }

    if [[ "${selected}" =~ S2S[[:space:]]Manager[[:space:]]TEMP[[:space:]]([A-Za-z0-9_-]+) ]]; then
        id="${BASH_REMATCH[1]}"
        if load_ufw_temp_rule "${id}"; then
            build_ufw_rule_args "${UFW_TEMP_PORT}" "${UFW_TEMP_PROTO}" "${UFW_TEMP_SOURCE}"
            if ! ufw --force delete "${UFW_RULE_ARGS[@]}" comment "${UFW_TEMP_COMMENT}" >/dev/null 2>&1; then
                ufw --force delete "${number}" >/dev/null || { error "UFW could not delete the rule."; pause; return 1; }
            fi
            remove_ufw_temp_timer_files "${id}"
        else
            ufw --force delete "${number}" >/dev/null || { error "UFW could not delete the rule."; pause; return 1; }
        fi
    else
        ufw --force delete "${number}" >/dev/null || { error "UFW could not delete the rule."; pause; return 1; }
    fi

    ok "UFW rule deleted."
    pause
}

install_ufw_from_management_menu() {
    local choice ssh_port

    banner
    section "INSTALL UFW SAFELY"

    cat <<'EOF'
UFW is currently not installed.

Installing the package alone does not replace a provider/cloud firewall.
Before UFW is ever enabled, every required incoming service must have an
allow rule. Otherwise remote services can become unreachable.

Examples:
  SSH             configured TCP administration port
  HTTP            TCP 80
  HTTPS           TCP 443
  IKE             UDP 500
  IPsec NAT-T     UDP 4500
  WireGuard       configured UDP listen port (normally 51820)

This installation path prepares an SSH allow rule first and deliberately
leaves UFW disabled. Existing S2S and WireGuard firewall rules are not
guessed or changed here. They can be reviewed before UFW is enabled later.
EOF

    ssh_port="$(detect_ssh_port)"
    echo
    echo "Detected SSH port: TCP ${ssh_port}"
    echo
    echo "  [1] Install UFW and prepare the SSH safety rule"
    echo "  [B] Back"
    echo "  [E] Exit"
    echo
    read -r -p "Selection: " choice

    case "${choice}" in
        1) ;;
        b|B|0) return 0 ;;
        e|E) clear_screen; echo "Bye."; exit 0 ;;
        *) error "Invalid selection."; pause; return 1 ;;
    esac

    echo
    info "Installing UFW package..."
    if ! apt-get update >/tmp/s2s-manager-ufw-apt-update.log 2>&1; then
        error "Package index update failed."
        echo "See: /tmp/s2s-manager-ufw-apt-update.log"
        pause
        return 1
    fi
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y ufw \
        >/tmp/s2s-manager-ufw-apt-install.log 2>&1; then
        error "UFW installation failed."
        echo "See: /tmp/s2s-manager-ufw-apt-install.log"
        pause
        return 1
    fi

    if ! ufw allow "${ssh_port}/tcp" comment 'S2S Manager SSH safety' >/dev/null; then
        error "UFW was installed, but the SSH safety rule could not be created."
        warn "UFW will not be enabled by the manager."
        pause
        return 1
    fi

    echo
    ok "UFW installed."
    ok "SSH safety rule prepared for TCP ${ssh_port}."
    if ufw_rule_allows_port "${ssh_port}" tcp; then
        ok "The stored SSH allow rule was verified."
    else
        warn "The SSH rule could not be verified from UFW output."
    fi
    info "UFW remains disabled. No existing network traffic was blocked."
    echo
    echo "Use 'Show all firewall rules' to review the complete rule set."
    pause
}

ufw_boot_enabled() {
    grep -Eq '^[[:space:]]*ENABLED[[:space:]]*=[[:space:]]*yes[[:space:]]*$' /etc/ufw/ufw.conf 2>/dev/null
}

ufw_ssh_safety_rule_present() {
    local ssh_port="$1" ssh_client
    ssh_client="$(awk '{print $1}' <<< "${SSH_CONNECTION:-}")"
    if valid_ipv4 "${ssh_client}"; then
        access_check_ufw_allows_local_service "${ssh_port}" tcp "${ssh_client}/32"
    else
        ufw_rule_allows_port "${ssh_port}" tcp
    fi
}

enable_ufw_safely() {
    local ssh_port confirm output
    banner
    section "ENABLE UFW SAFELY"

    ufw_installed || { error "UFW is not installed."; pause; return 1; }
    if ufw_active; then
        info "UFW is already active."
        ufw_boot_enabled && ok "UFW is configured to load at boot." || warn "UFW boot configuration could not be confirmed."
        pause
        return 0
    fi

    ssh_port="$(detect_ssh_port)"
    echo "Detected SSH administration port: TCP ${ssh_port}"
    echo
    if ! ufw_ssh_safety_rule_present "${ssh_port}"; then
        error "No stored ALLOW IN rule covering the current SSH client on TCP ${ssh_port} was found."
        error "The manager refuses to enable UFW because the remote session could be locked out."
        echo
        echo "Add and review the SSH rule first, then run this safety check again."
        pause
        return 1
    fi
    ok "Stored SSH access rule verified for TCP ${ssh_port}."

    echo
    section "RULES THAT WILL BECOME ACTIVE"
    print_annotated_ufw_added_rules
    echo
    warn "Enabling UFW applies the stored rules immediately and enables UFW at boot."
    warn "Any service without a matching allow rule may become unreachable."
    info "Provider/cloud firewall rules remain separate."
    echo
    read -r -p "Type ENABLE to activate UFW now: " confirm
    [[ "${confirm}" == "ENABLE" ]] || { info "UFW was not enabled."; pause; return 0; }

    if ! output="$(ufw --force enable 2>&1)"; then
        error "UFW could not be enabled."
        [[ -n "${output}" ]] && printf '%s\n' "${output}"
        pause
        return 1
    fi
    [[ -n "${output}" ]] && printf '%s\n' "${output}"
    echo
    if ufw_active; then
        ok "UFW is active now."
    else
        error "The enable command completed, but UFW does not report active status."
        pause
        return 1
    fi
    if ufw_boot_enabled; then
        ok "UFW is enabled for automatic loading at boot."
    else
        error "UFW is active, but /etc/ufw/ufw.conf does not confirm boot activation."
        warn "Review the UFW package/service configuration before rebooting."
    fi
    pause
}

disable_ufw_safely() {
    local confirm output
    banner
    section "DISABLE UFW"
    ufw_installed || { error "UFW is not installed."; pause; return 1; }
    if ! ufw_active; then
        info "UFW is already inactive. Stored rules are preserved."
        pause
        return 0
    fi
    warn "Disabling UFW removes its active firewall protection immediately."
    echo "Stored rules are preserved, but UFW will also remain disabled after reboot."
    echo
    read -r -p "Type DISABLE to turn off UFW: " confirm
    [[ "${confirm}" == "DISABLE" ]] || { info "UFW remains active."; pause; return 0; }
    if ! output="$(ufw disable 2>&1)"; then
        error "UFW could not be disabled."
        [[ -n "${output}" ]] && printf '%s\n' "${output}"
        pause
        return 1
    fi
    [[ -n "${output}" ]] && printf '%s\n' "${output}"
    if ufw_active; then
        error "UFW still reports active status."
    else
        ok "UFW is inactive. Stored rules were preserved."
        ufw_boot_enabled && warn "Boot configuration still reports enabled; review /etc/ufw/ufw.conf." || ok "UFW is disabled at boot."
    fi
    pause
}

reload_ufw_safely() {
    local ssh_port confirm output
    banner
    section "RELOAD UFW"
    ufw_installed || { error "UFW is not installed."; pause; return 1; }
    ufw_active || { error "UFW is inactive. Enable it safely instead of reloading it."; pause; return 1; }
    ssh_port="$(detect_ssh_port)"
    if ! ufw_ssh_safety_rule_present "${ssh_port}"; then
        error "No ALLOW IN rule covering the current SSH client on TCP ${ssh_port} was found."
        error "The manager refuses to reload UFW because the remote session could be locked out."
        pause
        return 1
    fi
    echo "Reloading re-applies the complete stored UFW configuration."
    echo "Normal ufw allow/delete operations are applied immediately and usually need no reload."
    echo
    read -r -p "Reload UFW now? [y/N]: " confirm
    [[ "$(tr '[:upper:]' '[:lower:]' <<< "${confirm}")" == "y" ]] || { info "UFW was not reloaded."; pause; return 0; }
    if ! output="$(ufw reload 2>&1)"; then
        error "UFW reload failed."
        [[ -n "${output}" ]] && printf '%s\n' "${output}"
        pause
        return 1
    fi
    [[ -n "${output}" ]] && printf '%s\n' "${output}"
    ufw_active && ok "UFW reloaded and remains active." || error "UFW no longer reports active status after reload."
    pause
}

ufw_management_menu() {
    local choice status

    while :; do
        banner
        section "UFW FIREWALL MANAGEMENT"

        if ! ufw_installed; then
            info "UFW is not installed."
            echo "Provider/cloud firewall rules are separate and are not managed here."
            echo
            echo "  [1] Install UFW safely"
            echo "  [B] Back"
            echo "  [E] Exit"
            echo
            read -r -p "Selection: " choice
            case "${choice}" in
                1) install_ufw_from_management_menu ;;
                b|B|0) return ;;
                e|E) clear_screen; echo "Bye."; exit 0 ;;
                *) error "Invalid selection."; sleep 1 ;;
            esac
            continue
        fi

        if ufw_active; then
            status="ACTIVE"
            ok "UFW is installed and active."
        else
            status="INACTIVE"
            warn "UFW is installed but inactive."
            info "Stored rules are not currently filtering traffic."
        fi

        echo
        printf 'Status: %s\n' "${status}"
        if ufw_boot_enabled; then
            printf 'Boot:   ENABLED\n'
        else
            printf 'Boot:   DISABLED\n'
        fi
        echo
        echo "  [1] Show all firewall rules"
        echo "  [2] Add permanent ALLOW rule"
        echo "  [3] Add temporary ALLOW rule with expiry timer"
        echo "  [4] Delete firewall rule"
        echo "  [5] Enable UFW safely"
        echo "  [6] Disable UFW"
        echo "  [7] Reload UFW"
        echo "  [B] Back"
        echo "  [E] Exit"
        echo
        read -r -p "Selection: " choice

        case "${choice}" in
            1) show_all_ufw_rules ;;
            2) add_ufw_rule permanent ;;
            3) add_ufw_rule temporary ;;
            4) delete_ufw_rule ;;
            5) enable_ufw_safely ;;
            6) disable_ufw_safely ;;
            7) reload_ufw_safely ;;
            b|B|0) return ;;
            e|E) clear_screen; echo "Bye."; exit 0 ;;
            *) error "Invalid selection."; sleep 1 ;;
        esac
    done
}

ufw_comment_exists() {
    local comment="$1"
    local status
    status="$(ufw status 2>/dev/null || true)"
    grep -Fq "${comment}" <<< "${status}"
}

ensure_shared_firewall_rules() {
    local public_ip="$1"
    local choice ssh_port action proto port desc

    if ! ufw_installed; then
        clear
        banner
        section "OPTIONAL UFW FIREWALL SETUP"

        cat <<'EOF'
UFW is currently not installed.

UFW is NOT required for the S2S Manager.
An external/provider firewall can be used instead.

If UFW is installed and enabled, incoming connections that are not
explicitly allowed may be blocked.

IMPORTANT:
Before enabling UFW, make sure every service you still need is allowed.

Examples:
  SSH             TCP 22
  HTTP            TCP 80
  HTTPS           TCP 443
  IKE             UDP 500
  IPsec NAT-T     UDP 4500

Web servers, mail servers, VPN servers and other custom services are
NOT opened automatically.
EOF

        ssh_port="$(detect_ssh_port)"

        echo
        echo "Detected SSH port: TCP ${ssh_port}"
        echo
        echo "  [1] Install UFW and configure it safely"
        echo "  [2] Continue without UFW"
        echo "  [B] Back"
        echo "  [E] Exit"
        echo
        read -r -p "Selection: " choice

        case "${choice}" in
            1)
                apt-get update || return 1
                DEBIAN_FRONTEND=noninteractive apt-get install -y ufw || return 1

                # SSH first: never offer ufw enable without protecting remote access.
                ufw allow "${ssh_port}/tcp" comment 'S2S Manager SSH safety' >/dev/null || return 1
                ufw allow 500/udp comment 'S2S Manager IKE' >/dev/null || return 1
                ufw allow 4500/udp comment 'S2S Manager NAT-T' >/dev/null || return 1

                while true; do
                    clear
                    banner
                    section "UFW CONFIGURATION SUMMARY"
                    echo "Mandatory rules prepared by the manager:"
                    echo
                    printf "  TCP %-8s SSH / current remote access\n" "${ssh_port}"
                    printf "  UDP %-8s IPsec IKE\n" "500"
                    printf "  UDP %-8s IPsec NAT-T\n" "4500"
                    echo
                    echo "Existing UFW rules are preserved."
                    echo
                    echo "WARNING:"
                    echo "Other incoming ports may be blocked after UFW is enabled unless"
                    echo "matching allow rules already exist or are added now."
                    echo
                    echo "  [1] Add additional firewall rule"
                    echo "  [2] Review and continue"
                    echo "  [B] Back (UFW remains disabled)"
                    echo "  [E] Exit"
                    echo
                    read -r -p "Selection: " action

                    case "${action}" in
                        1)
                            echo
                            read -r -p "Protocol [tcp]: " proto
                            proto="${proto:-tcp}"
                            proto="${proto,,}"
                            if [[ "${proto}" != "tcp" && "${proto}" != "udp" ]]; then
                                error "Protocol must be tcp or udp."
                                pause
                                continue
                            fi
                            read -r -p "Port: " port
                            if ! [[ "${port}" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
                                error "Port must be between 1 and 65535."
                                pause
                                continue
                            fi
                            read -r -p "Description [Additional service]: " desc
                            desc="${desc:-Additional service}"
                            ufw allow "${port}/${proto}" comment "S2S Manager ${desc}" >/dev/null || return 1
                            ok "Added ${proto^^} ${port} (${desc})"
                            pause
                            ;;
                        2) break ;;
                        b|B|0) return 0 ;;
                        e|E) clear_screen; echo "Bye."; exit 0 ;;
                    esac
                done

                clear
                banner
                section "FINAL UFW SAFETY CHECK"
                ufw status numbered || true
                echo
                echo "Current SSH access detected on TCP port ${ssh_port}."

                local ufw_status_check
                ufw_status_check="$(ufw status 2>/dev/null || true)"
                if grep -Eq "(^|[[:space:]])${ssh_port}/tcp[[:space:]]+ALLOW" <<< "${ufw_status_check}"; then
                    ok "Matching SSH allow rule is present."
                else
                    error "No matching SSH allow rule found."
                    echo "UFW will NOT be enabled."
                    pause
                    return 0
                fi

                echo
                echo "Default incoming policy will be DENY when UFW is enabled."
                echo "Review ALL required service ports above before continuing."
                echo
                read -r -p "Enable UFW now? [y/N]: " choice
                if [[ "${choice,,}" == "y" ]]; then
                    ufw default deny incoming >/dev/null
                    ufw default allow outgoing >/dev/null
                    ufw --force enable >/dev/null || return 1
                    ok "UFW enabled."
                else
                    info "UFW installed and rules prepared, but UFW was NOT enabled."
                fi
                return 0
                ;;
            2) return 0 ;;
            b|B|0) return 1 ;;
            e|E) clear_screen; echo "Bye."; exit 0 ;;
            *) return 1 ;;
        esac
    fi

    # UFW already exists. Add only the IPsec rules; never change its enabled state.
    if ! ufw_active; then
        info "UFW is installed but inactive."
        echo "The manager will not enable it automatically in this path."
        echo
        echo "  [1] Add managed IPsec rules and keep UFW disabled"
        echo "  [2] Skip firewall changes"
        echo "  [B] Back"
        echo "  [E] Exit"
        echo
        read -r -p "Selection: " choice
        case "${choice}" in
            1) ;;
            2) return 0 ;;
            b|B|0) return 1 ;;
            e|E) clear_screen; echo "Bye."; exit 0 ;;
            *) return 1 ;;
        esac
    fi

    ufw_comment_exists "S2S Manager IKE" ||
        ufw allow 500/udp comment 'S2S Manager IKE' >/dev/null
    ufw_comment_exists "S2S Manager NAT-T" ||
        ufw allow 4500/udp comment 'S2S Manager NAT-T' >/dev/null

    ok "Managed IPsec firewall rules are present (UDP 500 / 4500)."
}

remove_managed_ufw_rules() {
    ufw_installed || return 0

    local numbers
    numbers=$(
        ufw status numbered 2>/dev/null |
        awk '/S2S Manager (IKE|NAT-T)/ {
            gsub(/\[|\]/,"",$1)
            print $1
        }' |
        sort -rn
    )

    local n
    while read -r n; do
        [[ -n "${n}" ]] && yes | ufw delete "${n}" >/dev/null 2>&1 || true
    done <<< "${numbers}"
}

# ==============================================================================
# Generated system configuration
# ==============================================================================

render_strongswan_config_to_file() {
    local name="$1"
    local target="$2"
    load_tunnel "${name}" || return 1

    local psk escaped_psk remote_addrs start_action keyingtries_block
    psk="$(read_psk "${name}")" || return 1
    escaped_psk="$(strongswan_escape_string "${psk}")"

    case "${PEER_MODE}" in
        dynamic) remote_addrs="%any" ;;
        static|dns) remote_addrs="${PEER_ADDRESS}" ;;
        *) return 1 ;;
    esac

    # Debian <-> Debian peers should establish themselves after load/restart.
    # UniFi tunnels keep the established behavior where UniFi may initiate.
    start_action="none"
    keyingtries_block=""
    if [[ "${PEER_TYPE}" == "debian" ]]; then
        start_action="start"
        keyingtries_block=$'        # Keep retrying after temporary network/provider outages.\n        # A permanent negotiation error still stops the attempt.\n        keyingtries = 0\n'
    fi

    mkdir -p "$(dirname "${target}")"

    cat > "${target}" <<EOF
connections {
    ${MANAGED_PREFIX}-${NAME} {
        version = 2
        local_addrs = ${PUBLIC_IP}
        remote_addrs = ${remote_addrs}
        encap = yes

        proposals = aes256-sha256-modp2048

${keyingtries_block}        # UniFi IKE lifetime: 28800s (8h).
        # strongSwan's hard IKE lifetime is rekey_time + over_time.
        rekey_time = 26182s
        over_time = 2618s
        rand_time = 2618s

        local {
            auth = psk
            id = ${PUBLIC_IP}
        }

        remote {
            auth = psk
            id = ${AUTH_ID}
        }

        children {
            ${MANAGED_PREFIX}-${NAME} {
                local_ts = 0.0.0.0/0
                remote_ts = 0.0.0.0/0

                esp_proposals = aes256-sha256-modp2048

                # UniFi ESP lifetime: 3600s (1h).
                # Rekey early to avoid both peers reaching the hard lifetime together.
                life_time = 3600s
                rekey_time = 3273s
                rand_time = 327s

                mark_in = ${VTI_KEY}
                mark_out = ${VTI_KEY}

                start_action = ${start_action}
                dpd_action = restart
            }
        }

        dpd_delay = 30s
        reauth_time = 0s
    }
}

secrets {
    ike-${MANAGED_PREFIX}-${NAME} {
        id-local = ${PUBLIC_IP}
        id-remote = ${AUTH_ID}
        secret = "${escaped_psk}"
    }
}
EOF

    chmod 600 "${target}"
}

render_strongswan_config() {
    local name="$1"
    mkdir -p "${SWANCTL_DIR}"
    render_strongswan_config_to_file "${name}" "$(managed_swan_file "${name}")"
}
render_vti_script() {
    local name="$1"
    load_tunnel "${name}" || return 1

    local script
    script="$(managed_vti_script "${name}")"

    cat > "${script}" <<EOF
#!/usr/bin/env bash
set -e

PEER_MODE=$(printf '%q' "${PEER_MODE}")
PEER_ADDRESS=$(printf '%q' "${PEER_ADDRESS}")
REMOTE_ENDPOINT="0.0.0.0"

if [[ "\${PEER_MODE}" == "static" ]]; then
    REMOTE_ENDPOINT="\${PEER_ADDRESS}"
elif [[ "\${PEER_MODE}" == "dns" ]]; then
    command -v getent >/dev/null 2>&1 || {
        echo "getent is required to resolve VTI peer hostname '\${PEER_ADDRESS}'" >&2
        exit 1
    }

    mapfile -t REMOTE_IPS < <(
        getent ahostsv4 "\${PEER_ADDRESS}" 2>/dev/null |
        awk '{print \$1}' |
        sort -u
    )

    if (( \${#REMOTE_IPS[@]} == 0 )); then
        echo "Could not resolve VTI peer hostname '\${PEER_ADDRESS}' to IPv4" >&2
        exit 1
    fi

    if (( \${#REMOTE_IPS[@]} > 1 )); then
        echo "Peer hostname '\${PEER_ADDRESS}' resolves to multiple IPv4 addresses:" >&2
        printf '  %s\\n' "\${REMOTE_IPS[@]}" >&2
        echo "Classic VTI requires exactly one remote endpoint." >&2
        exit 1
    fi

    REMOTE_ENDPOINT="\${REMOTE_IPS[0]}"
fi

if ip link show ${VTI_INTERFACE} >/dev/null 2>&1; then
    if [[ "\${PEER_MODE}" != "dynamic" ]]; then
        CURRENT_REMOTE="\$(
            ip -d link show ${VTI_INTERFACE} 2>/dev/null |
            awk '/vti / {
                for (i=1; i<=NF; i++) {
                    if (\$i=="remote" && (i+1)<=NF) { print \$(i+1); exit }
                }
            }'
        )"

        [[ "\${CURRENT_REMOTE}" == "any" ]] && CURRENT_REMOTE="0.0.0.0"

        if [[ -n "\${CURRENT_REMOTE}" && "\${CURRENT_REMOTE}" != "\${REMOTE_ENDPOINT}" ]]; then
            ip link del ${VTI_INTERFACE}
        fi
    fi
fi

ip link show ${VTI_INTERFACE} >/dev/null 2>&1 || \\
ip tunnel add ${VTI_INTERFACE} \\
    local ${PUBLIC_IP} \\
    remote "\${REMOTE_ENDPOINT}" \\
    mode vti \\
    key ${VTI_KEY}

ip link set ${VTI_INTERFACE} up

grep -q '${DEBIAN_VTI_IP}/30' < <(ip addr show dev ${VTI_INTERFACE}) || \\
ip addr add ${DEBIAN_VTI_IP}/30 dev ${VTI_INTERFACE}

ip route replace ${VTI_NETWORK} dev ${VTI_INTERFACE} table 220
EOF

    local route
    while read -r route; do
        [[ -n "${route}" ]] &&
            printf 'ip route replace %s dev %s table 220\n' "${route}" "${VTI_INTERFACE}" >> "${script}"
    done < <(read_routes "${name}")

    cat >> "${script}" <<EOF

sysctl -w net.ipv4.conf.${VTI_INTERFACE}.disable_policy=1 >/dev/null
sysctl -w net.ipv4.conf.${VTI_INTERFACE}.rp_filter=0 >/dev/null
EOF

    chmod 755 "${script}"
}

render_systemd_service() {
    local name="$1"
    load_tunnel "${name}" || return 1

    cat > "$(managed_service_file "${name}")" <<EOF
[Unit]
Description=IPsec S2S VTI - ${NAME}
After=network-online.target
Wants=network-online.target
Before=strongswan.service

[Service]
Type=oneshot
ExecStart=$(managed_vti_script "${name}")
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
}

mark_tunnel_installed() {
    local name="$1"
    load_tunnel "${name}" || return 1

    save_tunnel \
        "${NAME}" "${PUBLIC_IP}" "${AUTH_ID}" "${VTI_INTERFACE}" "${VTI_KEY}" \
        "${VTI_NETWORK}" "${DEBIAN_VTI_IP}" "${UNIFI_VTI_IP}" "1" \
        "${PEER_MODE}" "${PEER_ADDRESS}" "${DISPLAY_NAME}" "${PEER_TYPE}"
}

mark_tunnel_defined() {
    local name="$1"
    load_tunnel "${name}" || return 1

    save_tunnel \
        "${NAME}" "${PUBLIC_IP}" "${AUTH_ID}" "${VTI_INTERFACE}" "${VTI_KEY}" \
        "${VTI_NETWORK}" "${DEBIAN_VTI_IP}" "${UNIFI_VTI_IP}" "0" \
        "${PEER_MODE}" "${PEER_ADDRESS}" "${DISPLAY_NAME}" "${PEER_TYPE}"
}


install_artifacts_present() {
    local name="$1"

    [[ -e "$(managed_swan_file "${name}")" ]] && return 0
    [[ -e "$(managed_vti_script "${name}")" ]] && return 0
    [[ -e "$(managed_service_file "${name}")" ]] && return 0
    [[ -L "${SYSTEMD_DIR}/multi-user.target.wants/$(managed_service_name "${name}")" ]] && return 0

    load_tunnel "${name}" >/dev/null 2>&1 || return 1
    systemctl is-active --quiet "$(managed_service_name "${name}")" 2>/dev/null && return 0
    systemctl is-failed --quiet "$(managed_service_name "${name}")" 2>/dev/null && return 0

    return 1
}

cleanup_partial_install() {
    local name="$1"
    load_tunnel "${name}" || return 1

    section "CLEANING PARTIAL INSTALLATION"

    printf '[1/5] Stopping / disabling tunnel service... '
    systemctl disable --now "$(managed_service_name "${name}")" \
        >/tmp/s2s-manager-install-clean-service.log 2>&1 || true
    printf '%b\n' "${C_GREEN}OK${C_RESET}"

    printf '[2/5] Removing partial VTI interface... '
    ip link del "${VTI_INTERFACE}" >/tmp/s2s-manager-install-clean-vti.log 2>&1 || true
    printf '%b\n' "${C_GREEN}OK${C_RESET}"

    printf '[3/5] Removing manager-generated files... '
    rm -f \
        "$(managed_swan_file "${name}")" \
        "$(managed_vti_script "${name}")" \
        "$(managed_service_file "${name}")" \
        "${SYSTEMD_DIR}/multi-user.target.wants/$(managed_service_name "${name}")"
    printf '%b\n' "${C_GREEN}OK${C_RESET}"

    printf '[4/5] Reloading systemd / strongSwan... '
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl reset-failed "$(managed_service_name "${name}")" >/dev/null 2>&1 || true
    swanctl_clean swanctl --load-all >/tmp/s2s-manager-install-clean-swan.log 2>&1 || true
    printf '%b\n' "${C_GREEN}OK${C_RESET}"

    printf '[5/5] Keeping tunnel definition in DEFINED state... '
    mark_tunnel_defined "${name}" >/dev/null 2>&1 || true
    printf '%b\n' "${C_GREEN}OK${C_RESET}"

    echo
    ok "Partial installation artifacts cleaned."
    info "Tunnel definition and PSK were kept."
}

install_rollback() {
    local name="$1"
    local failed_step="$2"
    local remove_shared_firewall="${3:-0}"

    load_tunnel "${name}" || return 1

    echo
    section "INSTALLATION ROLLBACK"

    warn "Installation failed at: ${failed_step}"
    echo "The manager is reverting files/services created for this tunnel."
    echo

    printf '[1/6] Stopping / disabling tunnel service... '
    systemctl disable --now "$(managed_service_name "${name}")" \
        >/tmp/s2s-manager-install-rollback-service.log 2>&1 || true
    printf '%b\n' "${C_GREEN}OK${C_RESET}"

    printf '[2/6] Removing VTI interface... '
    ip link del "${VTI_INTERFACE}" >/tmp/s2s-manager-install-rollback-vti.log 2>&1 || true
    printf '%b\n' "${C_GREEN}OK${C_RESET}"

    printf '[3/6] Removing generated manager files... '
    rm -f \
        "$(managed_swan_file "${name}")" \
        "$(managed_vti_script "${name}")" \
        "$(managed_service_file "${name}")" \
        "${SYSTEMD_DIR}/multi-user.target.wants/$(managed_service_name "${name}")"
    printf '%b\n' "${C_GREEN}OK${C_RESET}"

    printf '[4/6] Reloading systemd / strongSwan... '
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl reset-failed "$(managed_service_name "${name}")" >/dev/null 2>&1 || true
    swanctl_clean swanctl --load-all >/tmp/s2s-manager-install-rollback-swan.log 2>&1 || true
    printf '%b\n' "${C_GREEN}OK${C_RESET}"

    printf '[5/6] Restoring manager state to DEFINED... '
    mark_tunnel_defined "${name}" >/dev/null 2>&1 || true
    printf '%b\n' "${C_GREEN}OK${C_RESET}"

    printf '[6/6] Shared firewall rules... '
    if [[ "${remove_shared_firewall}" == "1" ]] && ufw_installed; then
        remove_managed_ufw_rules >/dev/null 2>&1 || true
        printf '%b\n' "${C_GREEN}REMOVED${C_RESET}"
    else
        printf '%b\n' "${C_CYAN}UNCHANGED${C_RESET}"
    fi

    echo
    ok "Installation rollback completed."
    info "Tunnel definition and PSK were kept."
}

find_wildcard_vti_conflict() {
    local public_ip="$1"
    local ignore_interface="${2:-}"
    local current_iface="" line

    VTI_TOPOLOGY_CONFLICT_INTERFACE=""

    command_available ip || return 1

    while IFS= read -r line; do
        if [[ "${line}" =~ ^[0-9]+:\ ([^:@]+) ]]; then
            current_iface="${BASH_REMATCH[1]}"
            continue
        fi

        [[ -z "${current_iface}" ]] && continue
        [[ -n "${ignore_interface}" && "${current_iface}" == "${ignore_interface}" ]] && continue

        if [[ "${line}" == *"vti remote any local ${public_ip}"* ]]; then
            VTI_TOPOLOGY_CONFLICT_INTERFACE="${current_iface}"
            return 0
        fi
    done < <(ip -d link show type vti 2>/dev/null)

    return 1
}

find_specific_vti_conflict() {
    local public_ip="$1"
    local remote_ip="$2"
    local ignore_interface="${3:-}"
    local current_iface="" line

    VTI_TOPOLOGY_CONFLICT_INTERFACE=""

    command_available ip || return 1

    while IFS= read -r line; do
        if [[ "${line}" =~ ^[0-9]+:\ ([^:@]+) ]]; then
            current_iface="${BASH_REMATCH[1]}"
            continue
        fi

        [[ -z "${current_iface}" ]] && continue
        [[ -n "${ignore_interface}" && "${current_iface}" == "${ignore_interface}" ]] && continue

        if [[ "${line}" == *"vti remote ${remote_ip} local ${public_ip}"* ]]; then
            VTI_TOPOLOGY_CONFLICT_INTERFACE="${current_iface}"
            return 0
        fi
    done < <(ip -d link show type vti 2>/dev/null)

    return 1
}

check_vti_install_topology() {
    local name="$1"
    load_tunnel "${name}" || return 1

    local remote_ip=""

    case "${PEER_MODE}" in
        dynamic)
            if find_wildcard_vti_conflict "${PUBLIC_IP}" "${VTI_INTERFACE}"; then
                validation_error_block \
                    "VTI TOPOLOGY CONFLICT" \
                    "Peer mode:            Dynamic / unknown" \
                    "Requested interface:  ${VTI_INTERFACE}" \
                    "Local public IP:      ${PUBLIC_IP}" \
                    "Existing VTI:         ${VTI_TOPOLOGY_CONFLICT_INTERFACE}" \
                    "Reason:               another wildcard-remote VTI already uses this local endpoint" \
                    "" \
                    "Use a Static IPv4 or Dynamic DNS peer for an additional VTI tunnel," \
                    "or keep this tunnel definition uninstalled."
                return 1
            fi
            ;;
        static)
            remote_ip="${PEER_ADDRESS}"
            ;;
        dns)
            PEER_RESOLVED_IP=""
            PEER_RESOLVE_MULTIPLE=""
            resolve_peer_hostname "${PEER_ADDRESS}"
            case "$?" in
                0)
                    remote_ip="${PEER_RESOLVED_IP}"
                    ;;
                1)
                    validation_error_block \
                        "PEER DNS RESOLUTION FAILED" \
                        "Hostname:  ${PEER_ADDRESS}" \
                        "The hostname currently has no resolvable IPv4 address." \
                        "No installation changes were applied."
                    return 1
                    ;;
                2)
                    validation_error_block \
                        "DNS CHECK UNAVAILABLE" \
                        "The 'getent' command is unavailable." \
                        "It is required for Dynamic DNS VTI endpoints."
                    return 1
                    ;;
                3)
                    validation_error_block \
                        "MULTIPLE PEER IPV4 ADDRESSES" \
                        "Hostname:  ${PEER_ADDRESS}" \
                        "IPv4s:     ${PEER_RESOLVE_MULTIPLE}" \
                        "Classic VTI requires exactly one remote endpoint."
                    return 1
                    ;;
            esac
            ;;
        *)
            error "Unknown peer mode '${PEER_MODE}'."
            return 1
            ;;
    esac

    if [[ -n "${remote_ip}" ]] &&
       find_specific_vti_conflict "${PUBLIC_IP}" "${remote_ip}" "${VTI_INTERFACE}"; then
        validation_error_block \
            "VTI ENDPOINT CONFLICT" \
            "Requested interface:  ${VTI_INTERFACE}" \
            "Local public IP:      ${PUBLIC_IP}" \
            "Peer endpoint:        ${remote_ip}" \
            "Existing VTI:         ${VTI_TOPOLOGY_CONFLICT_INTERFACE}" \
            "Reason:               this local/remote endpoint pair is already used" \
            "" \
            "Different DNS names that resolve to the same IPv4 address do not create" \
            "different VTI endpoints."
        return 1
    fi

    INSTALL_PEER_RESOLVED_IP="${remote_ip}"
    return 0
}

install_tunnel_system_config() {
    local name="$1"

    preflight_ready || {
        error "System prerequisites are not ready."
        pause
        return 1
    }

    load_tunnel "${name}" || return 1

    # A previous failed install may have left manager-owned files or a failed
    # oneshot service even though the state correctly remained DEFINED.
    if [[ "${INSTALLED}" != "1" ]] && install_artifacts_present "${name}"; then
        section "PARTIAL INSTALLATION DETECTED"
        warn "Manager-owned artifacts from an earlier incomplete installation were found."
        echo
        echo "The tunnel definition and PSK are safe and will be kept."
        echo "Only manager-generated system files/service/interface for '${name}' will be removed."
        echo

        if confirm_yes_no "Clean the partial installation now?" "Y"; then
            cleanup_partial_install "${name}"
            load_tunnel "${name}" || return 1
        else
            info "Installation cancelled. No further changes were made."
            pause
            return 1
        fi
    fi

    section "INSTALLATION PLAN"

    printf '%-28s %s\n' "Display name:" "${DISPLAY_NAME}"
    printf '%-28s %s\n' "Internal name:" "${NAME}"
    printf '%-28s %s\n' "Peer type:" "$(peer_type_label "${PEER_TYPE}")"
    printf '%-28s %s\n' "Local Debian public IP:" "${PUBLIC_IP}"
    printf '%-28s %s\n' "VTI interface:" "${VTI_INTERFACE}"
    printf '%-28s %s\n' "VTI network:" "${VTI_NETWORK}"
    printf '%-28s %s\n' "Local Debian VTI IP:" "${DEBIAN_VTI_IP}"
    if [[ "${PEER_TYPE}" == "debian" ]]; then
        printf '%-28s %s\n' "Remote Debian VTI IP:" "${UNIFI_VTI_IP}"
    else
        printf '%-28s %s\n' "UniFi VTI IP:" "${UNIFI_VTI_IP}"
    fi
    printf '%-28s %s\n' "Authentication ID:" "${AUTH_ID}"
    printf '%-28s %s\n' "Peer mode:" "$(peer_mode_label "${PEER_MODE}")"
    if [[ "${PEER_MODE}" != "dynamic" ]]; then
        printf '%-28s %s\n' "Peer address:" "${PEER_ADDRESS}"
    fi

    echo
    echo "Peer / connection behavior:"
    if [[ "${PEER_TYPE}" == "debian" ]]; then
        echo "  • This Debian server will automatically initiate the IPsec connection."
        echo "  • The remote Debian peer must have the mirrored configuration installed."
        echo "  • If the remote peer is not ready yet, DISCONNECTED is expected."
        echo "  • A local VTI/systemd failure is not caused by a missing remote peer."
    else
        echo "  • The UniFi side does NOT need to be configured yet."
        echo "  • Local Debian installation should still complete successfully."
        echo "  • Until UniFi is configured, DISCONNECTED is an expected state."
        echo "  • A local VTI/systemd failure is NOT caused by a missing UniFi peer."
    fi
    echo
    echo "System changes:"
    echo "  + managed strongSwan connection"
    echo "  + managed VTI startup script"
    echo "  + managed systemd VTI service"
    echo "  + table 220 return routes"
    echo "  + shared UFW IPsec rules for UDP 500 / 4500 (if UFW is available)"
    echo
    echo "Failure handling:"
    echo "  • If an installation step fails, generated tunnel files/services are rolled back."
    echo "  • The tunnel definition and PSK remain available for correction/retry."
    echo

    # Important: check the Linux VTI topology BEFORE firewall/files/systemd changes.
    if ! check_vti_install_topology "${name}"; then
        pause
        return 1
    fi

    validation_success "Local VTI topology check passed"
    if [[ "${PEER_MODE}" == "dns" ]]; then
        printf '%-28s %s\n' "Resolved peer IPv4:" "${INSTALL_PEER_RESOLVED_IP}"
        info "If this DNS address changes later, Re-apply the tunnel to update the VTI endpoint."
    fi

    confirm_yes_no "Install this tunnel on the Debian system?" "N" || return

    local installed_before remove_shared_firewall_on_rollback=0
    installed_before="$(installed_tunnel_count)"

    ensure_shared_firewall_rules "${PUBLIC_IP}" || {
        error "Firewall step cancelled or failed."
        pause
        return 1
    }

    # If there were no installed manager tunnels before this attempt, any
    # manager-owned UFW rules can be removed again during rollback.
    if (( installed_before == 0 )); then
        remove_shared_firewall_on_rollback=1
    fi

    echo
    section "INSTALLING TUNNEL"

    printf '[1/6] Writing strongSwan configuration... '
    if render_strongswan_config "${name}"; then
        printf '%b\n' "${C_GREEN}OK${C_RESET}"
    else
        printf '%b\n' "${C_RED}FAILED${C_RESET}"
        install_rollback "${name}" "writing strongSwan configuration" "${remove_shared_firewall_on_rollback}"
        pause
        return 1
    fi

    printf '[2/6] Writing VTI script... '
    if render_vti_script "${name}"; then
        printf '%b\n' "${C_GREEN}OK${C_RESET}"
    else
        printf '%b\n' "${C_RED}FAILED${C_RESET}"
        install_rollback "${name}" "writing VTI script" "${remove_shared_firewall_on_rollback}"
        pause
        return 1
    fi

    printf '[3/6] Writing systemd service... '
    if render_systemd_service "${name}"; then
        printf '%b\n' "${C_GREEN}OK${C_RESET}"
    else
        printf '%b\n' "${C_RED}FAILED${C_RESET}"
        install_rollback "${name}" "writing systemd service" "${remove_shared_firewall_on_rollback}"
        pause
        return 1
    fi

    printf '[4/6] Reloading systemd... '
    if systemctl daemon-reload; then
        printf '%b\n' "${C_GREEN}OK${C_RESET}"
    else
        printf '%b\n' "${C_RED}FAILED${C_RESET}"
        install_rollback "${name}" "reloading systemd" "${remove_shared_firewall_on_rollback}"
        pause
        return 1
    fi

    printf '[5/6] Enabling / starting VTI service... '
    if systemctl enable --now "$(managed_service_name "${name}")" >/tmp/s2s-manager-vti.log 2>&1; then
        printf '%b\n' "${C_GREEN}OK${C_RESET}"
    else
        printf '%b\n' "${C_RED}FAILED${C_RESET}"
        cat /tmp/s2s-manager-vti.log
        install_rollback "${name}" "starting VTI service" "${remove_shared_firewall_on_rollback}"
        pause
        return 1
    fi

    printf '[6/6] Loading / verifying strongSwan configuration... '
    swanctl_clean swanctl --load-all >/tmp/s2s-manager-swanctl.log 2>&1 || true

    local loaded_conns_verify
    loaded_conns_verify="$(swanctl_clean swanctl --list-conns 2>/dev/null || true)"
    if grep -qE "^${MANAGED_PREFIX}-${name}:" <<< "${loaded_conns_verify}"; then
        printf '%b\n' "${C_GREEN}OK${C_RESET}"
    else
        printf '%b\n' "${C_RED}FAILED${C_RESET}"
        cat /tmp/s2s-manager-swanctl.log 2>/dev/null || true
        install_rollback "${name}" "loading/verifying strongSwan configuration" "${remove_shared_firewall_on_rollback}"
        pause
        return 1
    fi

    mark_tunnel_installed "${name}"

    echo
    ok "Tunnel '${DISPLAY_NAME}' is installed on Debian."
    if [[ "${PEER_TYPE}" == "debian" ]]; then
        info "This Debian peer is configured to initiate the IPsec connection automatically."
        info "If the remote Debian peer is not ready yet, DISCONNECTED is expected."
    else
        info "The UniFi peer may be configured later."
        info "Until then, DISCONNECTED is expected and does not mean installation failed."
    fi
    pause
}

remove_tunnel_system_config() {
    local name="$1"
    load_tunnel "${name}" || return 1

    warn "This will remove the managed system configuration for tunnel '${name}'."
    echo
    echo "It will remove:"
    echo "  - $(managed_swan_file "${name}")"
    echo "  - $(managed_vti_script "${name}")"
    echo "  - $(managed_service_file "${name}")"
    echo "  - ${VTI_INTERFACE} (if present)"
    echo
    echo "State / PSK files will be kept unless you delete the tunnel definition separately."
    echo

    confirm_yes_no "Remove installed tunnel configuration?" "N" || return

    systemctl disable --now "$(managed_service_name "${name}")" >/dev/null 2>&1 || true
    ip link del "${VTI_INTERFACE}" >/dev/null 2>&1 || true

    rm -f \
        "$(managed_swan_file "${name}")" \
        "$(managed_vti_script "${name}")" \
        "$(managed_service_file "${name}")"

    systemctl daemon-reload
    swanctl --load-all >/dev/null 2>&1 || true

    mark_tunnel_defined "${name}"

    if (( $(installed_tunnel_count) == 0 )) && ufw_installed; then
        echo
        warn "No other managed S2S tunnels are installed."
        if confirm_yes_no "Remove shared S2S Manager UFW rules?" "Y"; then
            remove_managed_ufw_rules
            ok "Managed UFW rules removed."
        fi
    fi

    ok "Installed system configuration removed."
    pause
}

installed_tunnel_count() {
    local count=0 name
    while read -r name; do
        [[ -z "${name}" ]] && continue
        load_tunnel "${name}" || continue
        [[ "${INSTALLED}" == "1" ]] && ((count += 1))
    done < <(list_tunnel_names)
    printf '%d' "${count}"
}


tunnel_is_installed() {
    local name="$1"

    # Primary source: manager state.
    if load_tunnel "${name}" 2>/dev/null && [[ "${INSTALLED:-0}" == "1" ]]; then
        return 0
    fi

    # Fallbacks: detect an actually installed manager-owned tunnel even if
    # the state flag is stale or was unexpectedly overwritten in memory.
    if [[ -f "$(managed_swan_file "${name}")" ]] ||
       [[ -f "$(managed_vti_script "${name}")" ]] ||
       [[ -f "$(managed_service_file "${name}")" ]]; then
        return 0
    fi

    local unit_files
    unit_files="$(systemctl list-unit-files "$(managed_service_name "${name}")" 2>/dev/null || true)"
    if grep -Fq "$(managed_service_name "${name}")" <<< "${unit_files}"; then
        return 0
    fi

    return 1
}


actual_install_state() {
    local name="$1"
    local conn service loaded_conns table220_routes
    local state_flag=0
    local swan_file=0 vti_script=0 service_file=0 service_enabled=0
    local service_active=0 vti_present=0 conn_loaded=0 route_present=0
    local -a missing=()
    local -a unexpected=()

    load_tunnel "${name}" >/dev/null 2>&1 || {
        ACTUAL_INSTALL_STATE="UNKNOWN"
        ACTUAL_INSTALL_DETAIL="manager definition cannot be loaded"
        return 1
    }

    if [[ "${MANAGEMENT}" == "IMPORTED" ]]; then
        ACTUAL_INSTALL_STATE="IMPORTED"
        ACTUAL_INSTALL_DETAIL="read-only imported tunnel"
        return 0
    fi

    [[ "${INSTALLED:-0}" == "1" ]] && state_flag=1
    [[ -f "$(managed_swan_file "${name}")" ]] && swan_file=1
    [[ -f "$(managed_vti_script "${name}")" ]] && vti_script=1
    [[ -f "$(managed_service_file "${name}")" ]] && service_file=1

    service="$(managed_service_name "${name}")"
    if systemctl is-enabled --quiet "${service}" 2>/dev/null; then
        service_enabled=1
    fi
    if systemctl is-active --quiet "${service}" 2>/dev/null; then
        service_active=1
    fi
    if ip link show "${VTI_INTERFACE}" >/dev/null 2>&1; then
        vti_present=1
    fi

    conn="${MANAGED_PREFIX}-${NAME}"
    if command_available swanctl; then
        loaded_conns="$(swanctl_clean swanctl --list-conns 2>/dev/null || true)"
        if grep -qE "^${conn}:" <<< "${loaded_conns}"; then
            conn_loaded=1
        fi
    fi

    table220_routes="$(ip route show table 220 2>/dev/null || true)"
    if grep -qE "^${VTI_NETWORK//./\\.}([[:space:]]|$).*dev[[:space:]]+${VTI_INTERFACE}([[:space:]]|$)" \
        <<< "${table220_routes}"; then
        route_present=1
    fi

    # A completely clean definition is DEFINED regardless of a stale INSTALLED=0 flag.
    if (( state_flag == 0 && swan_file == 0 && vti_script == 0 && service_file == 0 &&
          service_enabled == 0 && service_active == 0 && vti_present == 0 &&
          conn_loaded == 0 && route_present == 0 )); then
        ACTUAL_INSTALL_STATE="DEFINED"
        ACTUAL_INSTALL_DETAIL="definition exists; no managed system installation detected"
        return 0
    fi

    # Fully installed means both manager state and all expected live/system artifacts agree.
    if (( state_flag == 1 && swan_file == 1 && vti_script == 1 && service_file == 1 &&
          service_enabled == 1 && service_active == 1 && vti_present == 1 &&
          conn_loaded == 1 && route_present == 1 )); then
        ACTUAL_INSTALL_STATE="INSTALLED"
        ACTUAL_INSTALL_DETAIL="manager state and live Debian installation agree"
        return 0
    fi

    (( state_flag == 0 )) && unexpected+=("manager state says DEFINED")
    (( state_flag == 1 )) || true
    (( swan_file == 1 )) || missing+=("strongSwan config")
    (( vti_script == 1 )) || missing+=("VTI script")
    (( service_file == 1 )) || missing+=("systemd service file")
    (( service_enabled == 1 )) || missing+=("enabled systemd service")
    (( service_active == 1 )) || missing+=("active systemd service")
    (( vti_present == 1 )) || missing+=("VTI interface ${VTI_INTERFACE}")
    (( conn_loaded == 1 )) || missing+=("loaded strongSwan connection")
    (( route_present == 1 )) || missing+=("table 220 tunnel route")

    if (( state_flag == 1 )); then
        unexpected+=("manager state says INSTALLED")
    fi

    ACTUAL_INSTALL_STATE="PARTIAL"
    ACTUAL_INSTALL_DETAIL=""
    if (( ${#missing[@]} > 0 )); then
        ACTUAL_INSTALL_DETAIL="Missing: $(IFS=', '; echo "${missing[*]}")"
    fi
    if (( state_flag == 0 )); then
        if [[ -n "${ACTUAL_INSTALL_DETAIL}" ]]; then
            ACTUAL_INSTALL_DETAIL+="; "
        fi
        ACTUAL_INSTALL_DETAIL+="system artifacts exist although manager state is DEFINED"
    fi
    return 0
}

actual_install_state_label() {
    case "$1" in
        INSTALLED) printf '%s' "MANAGED" ;;
        DEFINED)   printf '%s' "DEFINED / MANAGED" ;;
        PARTIAL)   printf '%s' "PARTIAL / BROKEN" ;;
        IMPORTED)  printf '%s' "IMPORTED / READ-ONLY" ;;
        *)         printf '%s' "UNKNOWN" ;;
    esac
}

select_tunnel_for_operation() {
    local operation="$1"
    local -a names=() labels=() states=()
    local -a primary_idx=() secondary_idx=()
    local -a display_order=()
    local name state selection display

    while read -r name; do
        [[ -n "${name}" ]] || continue
        load_tunnel "${name}" || continue
        [[ "${MANAGEMENT}" == "IMPORTED" ]] && continue

        actual_install_state "${name}" || continue
        state="${ACTUAL_INSTALL_STATE}"
        display="${DISPLAY_NAME:-${NAME}}"

        case "${operation}:${state}" in
            install:DEFINED)
                names+=("${name}")
                labels+=("${display}")
                states+=("${state}")
                primary_idx+=("$(( ${#names[@]} - 1 ))")
                ;;
            install:PARTIAL)
                names+=("${name}")
                labels+=("${display}")
                states+=("${state}")
                secondary_idx+=("$(( ${#names[@]} - 1 ))")
                ;;
            uninstall:INSTALLED)
                names+=("${name}")
                labels+=("${display}")
                states+=("${state}")
                primary_idx+=("$(( ${#names[@]} - 1 ))")
                ;;
            uninstall:PARTIAL)
                names+=("${name}")
                labels+=("${display}")
                states+=("${state}")
                secondary_idx+=("$(( ${#names[@]} - 1 ))")
                ;;
            reapply:INSTALLED)
                names+=("${name}")
                labels+=("${display}")
                states+=("${state}")
                primary_idx+=("$(( ${#names[@]} - 1 ))")
                ;;
            reapply:PARTIAL)
                names+=("${name}")
                labels+=("${display}")
                states+=("${state}")
                secondary_idx+=("$(( ${#names[@]} - 1 ))")
                ;;
        esac
    done < <(list_tunnel_names)

    if (( ${#names[@]} == 0 )); then
        case "${operation}" in
            install)   info "No defined or incomplete managed tunnels are available for installation." ;;
            uninstall) info "No installed or incomplete managed tunnels are available for removal." ;;
            reapply)   info "No installed or incomplete managed tunnels are available for re-apply." ;;
        esac
        pause
        return 1
    fi

    echo
    local n=1 idx

    if (( ${#primary_idx[@]} > 0 )); then
        case "${operation}" in
            install)   printf '%b\n' "${C_GREEN}${C_BOLD}  READY TO INSTALL${C_RESET}" ;;
            uninstall) printf '%b\n' "${C_GREEN}${C_BOLD}  INSTALLED${C_RESET}" ;;
            reapply)   printf '%b\n' "${C_GREEN}${C_BOLD}  INSTALLED${C_RESET}" ;;
        esac

        for idx in "${primary_idx[@]}"; do
            printf '  [%d] %s\n' "${n}" "${labels[$idx]}"
            display_order[$n]="${idx}"
            ((n += 1))
        done
        echo
    fi

    if (( ${#secondary_idx[@]} > 0 )); then
        printf '%b\n' "${C_YELLOW}${C_BOLD}  PARTIAL / BROKEN${C_RESET}"

        for idx in "${secondary_idx[@]}"; do
            printf '  [%d] %s  [repair needed]\n' "${n}" "${labels[$idx]}"
            display_order[$n]="${idx}"
            ((n += 1))
        done
        echo
    fi

    echo "Enter tunnel number and press ENTER."
    echo "B = Back    E = Exit"
    echo
    read -r -p "Selection: " selection

    case "${selection}" in
        ""|b|B|0) return 1 ;;
        e|E) clear_screen; echo "Bye."; exit 0 ;;
    esac

    [[ "${selection}" =~ ^[0-9]+$ ]] || return 1
    (( selection >= 1 && selection < n )) || return 1

    idx="${display_order[$selection]}"
    SELECTED_TUNNEL="${names[$idx]}"
    SELECTED_ACTUAL_STATE="${states[$idx]}"
    return 0
}

# ==============================================================================
# Re-apply installed tunnel from saved state
# ==============================================================================

reapply_installed_tunnel() {
    local name="$1"
    local mode="${2:-changed}"

    load_tunnel "${name}" || return 1

    echo
    info "Tunnel '${name}' is currently installed."

    if [[ "${mode}" == "manual" ]]; then
        echo "The manager will regenerate and re-apply the Debian-side configuration"
        echo "from the currently saved tunnel definition."
    else
        echo "The saved configuration has changed."
        echo
        echo "The manager can re-apply the Debian-side configuration now."
    fi

    echo
    echo "The existing PSK is kept unchanged."
    if [[ "${PEER_TYPE}" == "debian" ]]; then
        echo "No remote Debian peer settings need to be changed."
    else
        echo "No UniFi-side settings need to be changed."
    fi
    echo

    if ! check_vti_install_topology "${name}"; then
        return 1
    fi

    if [[ "${PEER_MODE}" == "dns" ]]; then
        local old_remote
        old_remote="$(vti_current_remote_endpoint "${VTI_INTERFACE}" 2>/dev/null || true)"
        printf '%-28s %s\n' "DNS hostname:" "${PEER_ADDRESS}"
        printf '%-28s %s\n' "Resolved peer IPv4:" "${INSTALL_PEER_RESOLVED_IP}"
        [[ -n "${old_remote}" ]] && printf '%-28s %s\n' "Current VTI remote IPv4:" "${old_remote}"
        if [[ -n "${old_remote}" && "${old_remote}" != "${INSTALL_PEER_RESOLVED_IP}" ]]; then
            warn "DNS endpoint changed. Re-apply will replace the VTI remote endpoint."
        else
            ok "Dynamic DNS endpoint is current."
        fi
        echo
    fi

    if [[ "${mode}" == "manual" ]]; then
        confirm_yes_no "Re-apply this tunnel now?" "Y" || return 0
    else
        confirm_yes_no "Apply the updated configuration now?" "Y" || {
            warn "Change saved in manager state only."
            info "The installed tunnel still uses the previous generated configuration."
            return 0
        }
    fi

    section "RE-APPLYING TUNNEL"

    printf '[1/6] Rewriting strongSwan configuration... '
    render_strongswan_config "${name}" &&
        printf '%b\n' "${C_GREEN}OK${C_RESET}" ||
        { printf '%b\n' "${C_RED}FAILED${C_RESET}"; return 1; }

    printf '[2/6] Rewriting VTI script... '
    render_vti_script "${name}" &&
        printf '%b\n' "${C_GREEN}OK${C_RESET}" ||
        { printf '%b\n' "${C_RED}FAILED${C_RESET}"; return 1; }

    printf '[3/6] Rewriting systemd service... '
    render_systemd_service "${name}" &&
        printf '%b\n' "${C_GREEN}OK${C_RESET}" ||
        { printf '%b\n' "${C_RED}FAILED${C_RESET}"; return 1; }

    printf '[4/6] Reloading systemd... '
    systemctl daemon-reload &&
        printf '%b\n' "${C_GREEN}OK${C_RESET}" ||
        { printf '%b\n' "${C_RED}FAILED${C_RESET}"; return 1; }

    printf '[5/6] Re-applying VTI and routes... '
    if "$(managed_vti_script "${name}")" >/tmp/s2s-manager-reapply-vti.log 2>&1; then
        printf '%b\n' "${C_GREEN}OK${C_RESET}"
    else
        printf '%b\n' "${C_RED}FAILED${C_RESET}"
        cat /tmp/s2s-manager-reapply-vti.log
        return 1
    fi

    printf '[6/6] Reloading strongSwan configuration... '
    if swanctl --load-all >/tmp/s2s-manager-reapply-swanctl.log 2>&1; then
        printf '%b\n' "${C_GREEN}OK${C_RESET}"
    else
        printf '%b\n' "${C_RED}FAILED${C_RESET}"
        cat /tmp/s2s-manager-reapply-swanctl.log
        return 1
    fi

    echo
    ok "Updated configuration applied."
    return 0
}

manual_reapply_tunnel() {
    banner
    section "RE-APPLY INSTALLED TUNNEL"

    echo "Regenerates the manager-owned strongSwan, VTI and systemd configuration"
    echo "from the currently saved tunnel definition."
    echo "Use this after changing tunnel settings or to repair manager-owned configuration files."
    echo "The PSK and saved tunnel definition are not regenerated or changed."
    echo "An established IPsec SA is kept unless a reconnect is performed separately."
    echo

    select_tunnel_for_operation "reapply" || return

    local name="${SELECTED_TUNNEL}"
    load_tunnel "${name}" || return

    if [[ "${MANAGEMENT}" == "IMPORTED" ]]; then
        imported_readonly_notice "${name}"
        pause
        return
    fi


    actual_install_state "${name}" || return
    if [[ "${ACTUAL_INSTALL_STATE}" == "PARTIAL" ]]; then
        section "INCOMPLETE INSTALLATION DETECTED"
        warn "Re-apply cannot safely use an inconsistent live installation."
        printf '%-28s %s
' "Details:" "${ACTUAL_INSTALL_DETAIL}"
        echo
        echo "The manager can clean its system artifacts and rebuild the tunnel."
        confirm_yes_no "Repair this tunnel now?" "N" || return
        cleanup_partial_install "${name}"
        install_tunnel_system_config "${name}"
        return
    fi
    if [[ "${ACTUAL_INSTALL_STATE}" != "INSTALLED" ]]; then
        warn "Tunnel '${DISPLAY_NAME}' is not fully installed on Debian."
        pause
        return
    fi

    echo
    printf '%-28s %s\n' "Display name:" "${DISPLAY_NAME}"
    printf '%-28s %s\n' "Internal name:" "${NAME}"
    printf '%-28s %s\n' "Peer type:" "$(peer_type_label "${PEER_TYPE}")"
    printf '%-28s %s\n' "VTI interface:" "${VTI_INTERFACE}"
    printf '%-28s %s\n' "Tunnel network:" "${VTI_NETWORK}"
    printf '%-28s %s\n' "Authentication ID:" "${AUTH_ID}"
    echo
    info "Re-apply regenerates the manager-owned strongSwan, VTI and systemd"
    echo "configuration from the saved definition and reloads it."
    echo
    echo "The PSK is NOT regenerated."
    echo "The tunnel definition is NOT changed."
    if [[ "${PEER_TYPE}" == "unifi" ]]; then
        echo "The UniFi configuration is NOT changed."
    else
        echo "The remote Debian peer configuration is NOT changed."
    fi
    echo
    echo "IMPORTANT:"
    echo "An already established IPsec connection is kept active."
    echo "Changes that affect IKE or CHILD SAs may therefore take effect"
    echo "only during the next automatic rekey."
    echo

    reapply_installed_tunnel "${name}" "manual" || {
        error "Re-applying tunnel '${name}' failed."
        pause
        return 1
    }

    echo
    ok "Tunnel configuration successfully re-applied."
    echo
    info "The current IPsec connection was kept active."
    echo "Changes affecting IKE or CHILD SAs may become effective only"
    echo "during the next automatic rekey."
    echo

    while :; do
        echo "  [1] Reconnect tunnel now"
        echo "  [B] Back"
        echo "  [E] Exit"
        echo
        local choice
        read -r -p "Selection: " choice

        case "${choice}" in
            1)
                reconnect_tunnel_by_name "${name}"
                return
                ;;
            b|B|0|"")
                return
                ;;
            e|E)
                clear_screen
                echo "Bye."
                exit 0
                ;;
            *)
                error "Invalid selection."
                ;;
        esac
    done
}

reconnect_tunnel_by_name() {
    local name="$1"

    load_tunnel "${name}" || return 1

    actual_install_state "${name}" || return 1
    if [[ "${ACTUAL_INSTALL_STATE}" != "INSTALLED" ]]; then
        warn "Tunnel '${DISPLAY_NAME}' is not fully installed on Debian."
        [[ "${ACTUAL_INSTALL_STATE}" == "PARTIAL" ]] && printf '%-28s %s\n' "Details:" "${ACTUAL_INSTALL_DETAIL}"
        info "Use Install/Re-apply to repair the tunnel first."
        pause
        return 1
    fi

    local conn
    conn="$(tunnel_connection_name "${name}")" || return 1

    banner
    section "RECONNECT TUNNEL"

    printf '%-28s %s\n' "Display name:" "${DISPLAY_NAME}"
    printf '%-28s %s\n' "Internal name:" "${NAME}"
    printf '%-28s %s\n' "Peer type:" "$(peer_type_label "${PEER_TYPE}")"
    printf '%-28s %s\n' "VTI interface:" "${VTI_INTERFACE}"

    if [[ "${PEER_TYPE}" == "debian" ]]; then
        printf '%-28s %s\n' "Remote Debian VTI IP:" "${UNIFI_VTI_IP}"
        echo
        echo "Reconnect terminates the current IKE/CHILD SAs and then"
        echo "actively initiates a new connection to the remote Debian peer."
        echo
        echo "Traffic through the tunnel will be interrupted briefly."
        echo "The PSK and tunnel configuration are NOT changed."
    else
        printf '%-28s %s\n' "UniFi VTI IP:" "${UNIFI_VTI_IP}"
        echo
        echo "Reconnect terminates the current IKE/CHILD SAs."
        echo "The UniFi side will then establish a new IPsec connection."
        echo
        echo "Traffic through the tunnel will be interrupted briefly."
        echo "The PSK and tunnel configuration are NOT changed."
        echo
        echo "In testing, UniFi usually reconnects after about 10 seconds."
        echo "The manager will wait up to 60 seconds."
    fi

    echo
    confirm_yes_no "Reconnect tunnel now?" "N" || return 0

    section "RECONNECTING"

    printf '[1/3] Terminating current IPsec connection... '
    swanctl_clean swanctl --terminate --ike "${conn}" \
        >/tmp/s2s-manager-reconnect-terminate.log 2>&1 || true
    printf '%b\n' "${C_GREEN}OK${C_RESET}"

    if [[ "${PEER_TYPE}" == "debian" ]]; then
        printf '[2/3] Initiating Debian peer connection... '
        if swanctl_clean swanctl --initiate --child "${conn}" \
            >/tmp/s2s-manager-reconnect-initiate.log 2>&1; then
            printf '%b\n' "${C_GREEN}OK${C_RESET}"
        else
            printf '%b\n' "${C_RED}FAILED${C_RESET}"
            error "Could not initiate the Debian peer connection."
            echo
            cat /tmp/s2s-manager-reconnect-initiate.log 2>/dev/null || true
            echo
            info "The tunnel configuration was NOT changed."
            pause
            return 1
        fi

        printf '[3/3] Verifying IKE/CHILD SA and VTI connectivity... '
        local waited=0 state=""
        while (( waited < 15 )); do
            state="$(tunnel_connection_state "${name}")"
            if [[ "${state}" == "CONNECTED" ]]; then
                if ping -c 1 -W 2 "${UNIFI_VTI_IP}" >/tmp/s2s-manager-reconnect-ping.log 2>&1; then
                    printf '%b\n' "${C_GREEN}CONNECTED${C_RESET}"
                    ok "Tunnel '${DISPLAY_NAME}' reconnected successfully."
                else
                    printf '%b\n' "${C_YELLOW}CONNECTED / PING FAILED${C_RESET}"
                    warn "IKE/CHILD SA is established, but the remote Debian VTI IP did not answer yet."
                fi
                pause
                return 0
            fi
            sleep 1
            ((waited += 1))
        done

        printf '%b\n' "${C_RED}FAILED${C_RESET}"
        error "No active IKE/CHILD SA was detected after initiating the Debian peer connection."
        info "Use Tunnel diagnostics and recent strongSwan logs for troubleshooting."
        pause
        return 1
    fi

    printf '[2/3] Waiting for UniFi to reconnect... '
    local waited=0 state=""
    while (( waited < 60 )); do
        state="$(tunnel_connection_state "${name}")"
        if [[ "${state}" == "CONNECTED" ]]; then
            printf '%b\n' "${C_GREEN}CONNECTED${C_RESET}"
            break
        fi
        sleep 2
        ((waited += 2))
    done

    if [[ "${state}" != "CONNECTED" ]]; then
        printf '\n'
        error "UniFi did not reconnect within 60 seconds."
        echo
        echo "The tunnel configuration was NOT changed."
        echo "Use Tunnel diagnostics and recent strongSwan logs for troubleshooting."
        pause
        return 1
    fi

    printf '[3/3] Testing VTI connectivity... '
    if ping -c 3 -W 2 "${UNIFI_VTI_IP}" >/tmp/s2s-manager-reconnect-ping.log 2>&1; then
        printf '%b\n' "${C_GREEN}OK${C_RESET}"
    else
        printf '%b\n' "${C_YELLOW}WARNING${C_RESET}"
        warn "IPsec is connected, but the immediate UniFi VTI ping did not fully succeed."
    fi

    echo
    ok "Tunnel '${DISPLAY_NAME}' reconnected successfully."
    pause
    return 0
}

manual_reconnect_tunnel() {
    banner
    section "RECONNECT TUNNEL"

    echo "Terminates the current IKE/CHILD SAs and establishes a fresh IPsec connection."
    echo "Use this when changed IPsec settings must take effect immediately or when a tunnel"
    echo "is installed correctly but the current connection needs to be restarted."
    echo "The tunnel definition, PSK, VTI configuration and systemd files are not changed."
    echo "Traffic through the tunnel is interrupted briefly."
    echo
    select_tunnel || return

    local name="${SELECTED_TUNNEL}"
    load_tunnel "${name}" || return

    if [[ "${MANAGEMENT}" == "IMPORTED" ]]; then
        imported_readonly_notice "${name}"
        echo
    fi

    reconnect_tunnel_by_name "${name}"
}

# ==============================================================================
# Existing tunnel discovery / read-only import
# ==============================================================================

source_file_already_imported() {
    local wanted="$1"
    local name

    while read -r name; do
        [[ -z "${name}" ]] && continue
        load_tunnel "${name}" || continue
        if [[ "${MANAGEMENT}" == "IMPORTED" && "${SOURCE_SWAN_FILE}" == "${wanted}" ]]; then
            return 0
        fi
    done < <(list_tunnel_names)

    return 1
}

parse_source_connection() {
    local file="$1"

    DISC_CONN_NAME=""
    DISC_PUBLIC_IP=""
    DISC_AUTH_ID=""
    DISC_MARK=""
    DISC_PSK=""
    DISC_FORCED_NATT=0

    DISC_CONN_NAME="$(
        awk '
            /^[[:space:]]*connections[[:space:]]*\{/ {inside=1; next}
            inside && /^[[:space:]]*[A-Za-z0-9_.:-]+[[:space:]]*\{/ {
                line=$0
                gsub(/^[[:space:]]+/, "", line)
                sub(/[[:space:]]*\{.*/, "", line)
                print line
                exit
            }
        ' "${file}"
    )"

    DISC_PUBLIC_IP="$(
        awk -F= '
            /^[[:space:]]*local_addrs[[:space:]]*=/ {
                v=$2; gsub(/[[:space:]]/, "", v); print v; exit
            }
        ' "${file}"
    )"

    DISC_AUTH_ID="$(
        awk -F= '
            /^[[:space:]]*remote[[:space:]]*\{/ {remote=1; next}
            remote && /^[[:space:]]*id[[:space:]]*=/ {
                v=$2
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", v)
                print v
                exit
            }
            remote && /^[[:space:]]*\}/ {remote=0}
        ' "${file}"
    )"

    DISC_MARK="$(
        awk -F= '
            /^[[:space:]]*mark_in[[:space:]]*=/ {
                v=$2; gsub(/[[:space:]]/, "", v); print v; exit
            }
        ' "${file}"
    )"

    DISC_PSK="$(
        awk '
            /^[[:space:]]*secret[[:space:]]*=/ {
                v=$0
                sub(/^[^=]*=[[:space:]]*/, "", v)
                sub(/[[:space:]]*$/, "", v)
                if (v ~ /^".*"$/) {
                    sub(/^"/, "", v)
                    sub(/"$/, "", v)
                }
                print v
                exit
            }
        ' "${file}"
    )"

    if grep -Eq '^[[:space:]]*encap[[:space:]]*=[[:space:]]*yes([[:space:]]|$)' "${file}"; then
        DISC_FORCED_NATT=1
    fi

    [[ -n "${DISC_CONN_NAME}" && -n "${DISC_PUBLIC_IP}" && -n "${DISC_AUTH_ID}" && -n "${DISC_MARK}" ]]
}

find_vti_for_mark() {
    local mark="$1"
    local iface details

    DISC_VTI_INTERFACE=""
    DISC_VTI_CIDR=""

    while read -r iface; do
        [[ -z "${iface}" ]] && continue
        details="$(ip -d link show "${iface}" 2>/dev/null || true)"
        if grep -Eq "vti .*ikey (0\\.0\\.0\\.)?${mark}([[:space:]]|$)" <<< "${details}" || \
           grep -Eq "vti .*okey (0\\.0\\.0\\.)?${mark}([[:space:]]|$)" <<< "${details}"; then
            DISC_VTI_INTERFACE="${iface}"
            DISC_VTI_CIDR="$(ip -4 -o addr show dev "${iface}" 2>/dev/null | awk '{print $4}' | head -1)"
            return 0
        fi
    done < <(ip -o link show | awk -F': ' '{print $2}' | sed 's/@.*//')

    return 1
}

derive_import_network() {
    local cidr="$1"
    local ip prefix n base local_n

    [[ "${cidr}" == */* ]] || return 1
    ip="${cidr%%/*}"
    prefix="${cidr##*/}"
    [[ "${prefix}" == "30" ]] || return 1
    valid_ipv4 "${ip}" || return 1

    local_n="$(ipv4_to_int "${ip}")"
    base=$(( local_n & 0xFFFFFFFC ))

    DISC_VTI_NETWORK="$(int_to_ipv4 "${base}")/30"
    DISC_DEBIAN_VTI_IP="${ip}"

    if (( local_n == base + 1 )); then
        DISC_UNIFI_VTI_IP="$(int_to_ipv4 "$((base + 2))")"
    elif (( local_n == base + 2 )); then
        DISC_UNIFI_VTI_IP="$(int_to_ipv4 "$((base + 1))")"
    else
        return 1
    fi
}

find_source_vti_script() {
    local iface="$1"
    local mark="$2"
    local f

    DISC_VTI_SCRIPT=""

    while IFS= read -r f; do
        [[ -f "${f}" ]] || continue
        if grep -Fq "ip tunnel add ${iface}" "${f}" 2>/dev/null && \
           grep -Eq "key[[:space:]]+${mark}([[:space:]]|$)" "${f}" 2>/dev/null; then
            DISC_VTI_SCRIPT="${f}"
            return 0
        fi
    done < <(find /usr/local/sbin /usr/local/bin /root -maxdepth 3 -type f 2>/dev/null)

    return 1
}

find_source_service() {
    local script="$1"
    local f

    DISC_SERVICE=""
    [[ -n "${script}" ]] || return 1

    while IFS= read -r f; do
        [[ -f "${f}" ]] || continue
        if grep -Fq "ExecStart=${script}" "${f}" 2>/dev/null; then
            DISC_SERVICE="$(basename "${f}")"
            return 0
        fi
    done < <(find /etc/systemd/system /usr/lib/systemd/system -maxdepth 2 -type f -name '*.service' 2>/dev/null)

    return 1
}

discover_source_routes() {
    local iface="$1"
    local tunnel_net="$2"
    local script="$3"
    local route

    DISC_ROUTES=()

    if [[ -n "${script}" && -f "${script}" ]]; then
        while read -r route; do
            [[ -z "${route}" || "${route}" == "${tunnel_net}" ]] && continue
            valid_cidr "${route}" && DISC_ROUTES+=("${route}")
        done < <(
            awk -v dev="${iface}" '
                $1=="ip" && $2=="route" && $3=="replace" {
                    for (i=1; i<=NF; i++) {
                        if ($i=="dev" && $(i+1)==dev) {
                            print $4
                            break
                        }
                    }
                }
            ' "${script}"
        )
    else
        while read -r route; do
            [[ -z "${route}" || "${route}" == "${tunnel_net}" ]] && continue
            valid_cidr "${route}" && DISC_ROUTES+=("${route}")
        done < <(ip route show table 220 dev "${iface}" 2>/dev/null | awk '{print $1}')
    fi
}

source_connection_state() {
    local conn="$1"
    local sa
    sa="$(swanctl_clean swanctl --list-sas 2>/dev/null || true)"

    if grep -qE "^${conn}: .*ESTABLISHED" <<< "${sa}" && \
       awk -v c="${conn}:" '
           $0 ~ "^" c {show=1; next}
           show && /^[^[:space:]]/ {exit}
           show && /INSTALLED/ {found=1; exit}
           END {exit found ? 0 : 1}
       ' <<< "${sa}"; then
        printf 'CONNECTED'
    else
        printf 'DISCONNECTED'
    fi
}

discover_existing_tunnels() {
    banner
    section "DISCOVER EXISTING IPSEC TUNNELS"

    echo "Scans this Debian server for existing strongSwan/VTI tunnels that are not yet managed."
    echo "Discovered tunnels can be imported as read-only entries for inspection."
    echo "Importing does not immediately rewrite or take ownership of their existing configuration."
    echo

    echo "This scan is read-only."
    echo "It does NOT modify strongSwan, VTI interfaces, routing or systemd."
    echo

    local -a files=()
    local -a labels=()
    local f base conn
    local managed_count=0 imported_count=0

    shopt -s nullglob
    for f in "${SWANCTL_DIR}"/*.conf; do
        base="$(basename "${f}")"

        if [[ "${base}" == "${MANAGED_PREFIX}-"* ]]; then
            ((managed_count += 1))
            continue
        fi

        if source_file_already_imported "${f}"; then
            ((imported_count += 1))
            continue
        fi

        if parse_source_connection "${f}"; then
            files+=("${f}")
            labels+=("${DISC_CONN_NAME}")
        fi
    done
    shopt -u nullglob

    printf '%-32s %s\n' "Manager-owned configs skipped:" "${managed_count}"
    printf '%-32s %s\n' "Already imported configs skipped:" "${imported_count}"
    printf '%-32s %s\n' "Importable configs found:" "${#files[@]}"
    echo

    if (( ${#files[@]} == 0 )); then
        info "No unmanaged importable strongSwan tunnels were found."
        pause
        return
    fi

    local i selection
    for i in "${!files[@]}"; do
        printf '  [%d] %s\n' "$((i + 1))" "${labels[$i]}"
        printf '      %s\n' "${files[$i]}"
    done

    echo
    echo "Enter tunnel number and press ENTER."
    echo "B = Back    E = Exit"
    echo
    read -r -p "Selection: " selection

    case "${selection}" in
        ""|b|B|0) return ;;
        e|E) clear_screen; echo "Bye."; exit 0 ;;
    esac

    [[ "${selection}" =~ ^[0-9]+$ ]] || { error "Invalid selection."; pause; return; }
    (( selection >= 1 && selection <= ${#files[@]} )) || { error "Invalid selection."; pause; return; }

    local source_file="${files[$((selection - 1))]}"
    parse_source_connection "${source_file}" || {
        error "Could not parse the selected strongSwan configuration."
        pause
        return
    }

    find_vti_for_mark "${DISC_MARK}" || {
        error "Could not match VTI mark/key ${DISC_MARK} to an active VTI interface."
        pause
        return
    }

    derive_import_network "${DISC_VTI_CIDR}" || {
        error "Could not derive a /30 tunnel network from ${DISC_VTI_CIDR}."
        pause
        return
    }

    find_source_vti_script "${DISC_VTI_INTERFACE}" "${DISC_MARK}" || true
    find_source_service "${DISC_VTI_SCRIPT}" || true
    discover_source_routes "${DISC_VTI_INTERFACE}" "${DISC_VTI_NETWORK}" "${DISC_VTI_SCRIPT}"

    local conn_state
    conn_state="$(source_connection_state "${DISC_CONN_NAME}")"

    banner
    section "IMPORT PREVIEW"

    printf '%-28s %s\n' "Detected connection:" "${DISC_CONN_NAME}"
    printf '%-28s %s\n' "Connection state:" "${conn_state}"
    printf '%-28s %s\n' "Management:" "UNMANAGED / EXTERNAL"
    printf '%-28s %s\n' "strongSwan config:" "${source_file}"
    printf '%-28s %s\n' "Debian public IP:" "${DISC_PUBLIC_IP}"
    printf '%-28s %s\n' "Authentication ID:" "${DISC_AUTH_ID}"
    printf '%-28s %s\n' "VTI interface:" "${DISC_VTI_INTERFACE}"
    printf '%-28s %s\n' "VTI key / mark:" "${DISC_MARK}"
    printf '%-28s %s\n' "Tunnel network:" "${DISC_VTI_NETWORK}"
    printf '%-28s %s\n' "Debian VTI IP:" "${DISC_DEBIAN_VTI_IP}"
    printf '%-28s %s\n' "UniFi VTI IP:" "${DISC_UNIFI_VTI_IP}"
    printf '%-28s %s\n' "VTI startup script:" "${DISC_VTI_SCRIPT:-not detected}"
    printf '%-28s %s\n' "systemd service:" "${DISC_SERVICE:-not detected}"
    printf '%-28s %s\n' "Forced NAT-T:" "$([[ "${DISC_FORCED_NATT}" == "1" ]] && echo Yes || echo No)"
    printf '%-28s %s\n' "PSK:" "$([[ -n "${DISC_PSK}" ]] && echo detected || echo NOT detected)"

    echo
    echo "Remote networks:"
    if (( ${#DISC_ROUTES[@]} == 0 )); then
        echo "  None detected"
    else
        local r
        for r in "${DISC_ROUTES[@]}"; do
            printf '  • %s\n' "${r}"
        done
    fi

    echo
    echo "IMPORTANT:"
    echo "Import only creates S2S Manager state files."
    echo "The existing strongSwan, VTI and systemd configuration is NOT changed,"
    echo "renamed, disabled or removed."
    echo
    echo "Imported tunnels remain READ-ONLY until a later Take Over operation."
    echo "The detected PSK is copied into the manager secret store so it can be"
    echo "reused later without generating a new key."

    if [[ -z "${DISC_PSK}" ]]; then
        echo
        warn "No PSK was detected. Import is cancelled to avoid creating an incomplete state."
        pause
        return
    fi

    echo
    local suggested_name="${DISC_CONN_NAME}"
    if tunnel_exists "${suggested_name}"; then
        suggested_name="${DISC_CONN_NAME}-imported"
    fi

    local import_name="${suggested_name}"
    while tunnel_exists "${import_name}"; do
        import_name="${import_name}-1"
    done

    printf 'Manager name [%s]: ' "${import_name}"
    local entered_name
    read -r entered_name
    [[ -n "${entered_name}" ]] && import_name="${entered_name}"

    valid_tunnel_name "${import_name}" || {
        error "Invalid manager tunnel name."
        pause
        return
    }

    tunnel_exists "${import_name}" && {
        error "A manager tunnel named '${import_name}' already exists."
        pause
        return
    }

    echo
    confirm_yes_no "Import this tunnel into manager state?" "N" || return

    save_imported_tunnel \
        "${import_name}" "${DISC_PUBLIC_IP}" "${DISC_AUTH_ID}" \
        "${DISC_VTI_INTERFACE}" "${DISC_MARK}" "${DISC_VTI_NETWORK}" \
        "${DISC_DEBIAN_VTI_IP}" "${DISC_UNIFI_VTI_IP}" \
        "${DISC_CONN_NAME}" "${source_file}" "${DISC_VTI_SCRIPT}" \
        "${DISC_SERVICE}" "${DISC_FORCED_NATT}"

    write_routes "${import_name}" "${DISC_ROUTES[@]:-}"
    save_psk "${import_name}" "${DISC_PSK}"

    echo
    ok "Tunnel imported into S2S Manager state."
    echo
    info "Original system configuration remains untouched."
    info "PSK copied to manager secret store with mode 600."
    echo
    echo "State: IMPORTED / READ-ONLY"
    pause
}

# ==============================================================================
# Take Over imported tunnels
# ==============================================================================

takeover_wait_for_connection() {
    local name="$1"
    local timeout="${2:-60}"
    local conn="${MANAGED_PREFIX}-${name}"
    local sa=""
    local start end elapsed i

    start="$(date +%s)"

    for i in $(seq 1 "${timeout}"); do
        sa="$(swanctl_clean swanctl --list-sas 2>/dev/null || true)"

        if grep -qE "^${conn}: .*ESTABLISHED" <<< "${sa}" &&
           awk -v c="${conn}:" '
               $0 ~ "^" c {show=1; next}
               show && /^[^[:space:]]/ {exit}
               show && /INSTALLED/ {found=1; exit}
               END {exit found ? 0 : 1}
           ' <<< "${sa}"; then
            end="$(date +%s)"
            elapsed=$((end - start))
            TAKEOVER_RECONNECT_SECONDS="${elapsed}"
            return 0
        fi

        sleep 1
    done

    return 1
}

takeover_backup_file() {
    local source="$1"
    local backup_root="$2"
    local label="$3"

    [[ -n "${source}" && -f "${source}" ]] || return 0

    mkdir -p "${backup_root}"
    cp -a "${source}" "${backup_root}/${label}"
}

takeover_restore_file() {
    local backup="$1"
    local target="$2"

    [[ -f "${backup}" ]] || return 0
    mkdir -p "$(dirname "${target}")"
    cp -a "${backup}" "${target}"
}

takeover_rollback() {
    local name="$1"
    local old_conn="$2"
    local old_swan="$3"
    local old_vti_script="$4"
    local old_service="$5"
    local backup_root="$6"

    echo
    section "ROLLING BACK TAKE OVER"

    printf '[1/7] Terminating manager IPsec SA... '
    swanctl_clean swanctl --terminate --ike "${MANAGED_PREFIX}-${name}" \
        >/tmp/s2s-manager-takeover-rollback-terminate.log 2>&1 || true
    printf '%b\n' "${C_GREEN}OK${C_RESET}"

    printf '[2/7] Removing manager system files... '
    systemctl disable --now "$(managed_service_name "${name}")" >/dev/null 2>&1 || true
    rm -f "$(managed_swan_file "${name}")" \
          "$(managed_vti_script "${name}")" \
          "$(managed_service_file "${name}")"
    printf '%b\n' "${C_GREEN}OK${C_RESET}"

    printf '[3/7] Restoring original files... '
    [[ -n "${old_swan}" ]] &&
        takeover_restore_file "${backup_root}/strongswan.conf" "${old_swan}"
    [[ -n "${old_vti_script}" ]] &&
        takeover_restore_file "${backup_root}/vti-script" "${old_vti_script}"
    if [[ -n "${old_service}" ]]; then
        takeover_restore_file "${backup_root}/systemd-service" "${SYSTEMD_DIR}/${old_service}"
    fi
    printf '%b\n' "${C_GREEN}OK${C_RESET}"

    printf '[4/7] Reloading systemd... '
    systemctl daemon-reload
    printf '%b\n' "${C_GREEN}OK${C_RESET}"

    printf '[5/7] Re-enabling original VTI service... '
    if [[ -n "${old_service}" && -f "${SYSTEMD_DIR}/${old_service}" ]]; then
        systemctl enable --now "${old_service}" >/tmp/s2s-manager-takeover-rollback-service.log 2>&1 || true
    fi
    printf '%b\n' "${C_GREEN}OK${C_RESET}"

    printf '[6/7] Reloading original strongSwan configuration... '
    swanctl_clean swanctl --load-all >/tmp/s2s-manager-takeover-rollback-swan.log 2>&1 || true
    printf '%b\n' "${C_GREEN}OK${C_RESET}"

    printf '[7/7] Restoring imported manager state... '
    load_tunnel "${name}" || true
    save_imported_tunnel \
        "${name}" "${PUBLIC_IP}" "${AUTH_ID}" "${VTI_INTERFACE}" "${VTI_KEY}" \
        "${VTI_NETWORK}" "${DEBIAN_VTI_IP}" "${UNIFI_VTI_IP}" \
        "${old_conn}" "${old_swan}" "${old_vti_script}" "${old_service}" "${SOURCE_FORCED_NATT:-0}"
    printf '%b\n' "${C_GREEN}OK${C_RESET}"

    echo
    warn "Take Over was rolled back."
    echo "The original configuration files were restored from:"
    echo "  ${backup_root}"
    echo
    echo "UniFi should reconnect to the restored external configuration automatically."
}


takeover_analyze_old_service() {
    local service="$1"
    local unit_file="${SYSTEMD_DIR}/${service}"

    TAKEOVER_OLD_SERVICE_PRESENT=0
    TAKEOVER_OLD_SERVICE_ACTIVE=0
    TAKEOVER_OLD_SERVICE_STOP_HOOKS=0
    TAKEOVER_OLD_SERVICE_SAFE_STOP=0
    TAKEOVER_OLD_SERVICE_NOTE="No external systemd service detected."

    [[ -n "${service}" ]] || return 0

    if [[ -f "${unit_file}" ]]; then
        TAKEOVER_OLD_SERVICE_PRESENT=1
    fi

    if systemctl is-active --quiet "${service}" 2>/dev/null; then
        TAKEOVER_OLD_SERVICE_ACTIVE=1
    fi

    if [[ -f "${unit_file}" ]] &&
       grep -Eq '^[[:space:]]*ExecStop(Post)?[[:space:]]*=' "${unit_file}"; then
        TAKEOVER_OLD_SERVICE_STOP_HOOKS=1
    fi

    if [[ "${TAKEOVER_OLD_SERVICE_ACTIVE}" == "1" &&
          "${TAKEOVER_OLD_SERVICE_STOP_HOOKS}" == "0" ]]; then
        TAKEOVER_OLD_SERVICE_SAFE_STOP=1
        TAKEOVER_OLD_SERVICE_NOTE="Active; no ExecStop/ExecStopPost hooks detected. Safe state-only stop planned."
    elif [[ "${TAKEOVER_OLD_SERVICE_ACTIVE}" == "1" &&
            "${TAKEOVER_OLD_SERVICE_STOP_HOOKS}" == "1" ]]; then
        TAKEOVER_OLD_SERVICE_NOTE="Active; stop hooks detected. Manager will NOT automatically stop it."
    elif [[ "${TAKEOVER_OLD_SERVICE_ACTIVE}" == "0" ]]; then
        TAKEOVER_OLD_SERVICE_NOTE="Not active; no runtime stop required."
    fi
}

show_takeover_backups() {
    banner
    section "TAKE OVER BACKUPS"

    echo "Shows backups created automatically before the manager takes over an imported tunnel."
    echo "These backups preserve the original configuration from before manager ownership."
    echo "This page is read-only and does not restore or modify a tunnel."
    echo

    echo "Take Over backups are stored under:"
    echo "  ${BACKUP_DIR}"
    echo
    echo "They are retained after a successful Take Over and after rollback."
    echo "The manager does NOT automatically delete or prune these backups."
    echo

    if [[ ! -d "${BACKUP_DIR}" ]]; then
        info "No Take Over backups found."
        pause
        return
    fi

    local -a backups=()
    local d
    while IFS= read -r d; do
        backups+=("${d}")
    done < <(find "${BACKUP_DIR}" -mindepth 1 -maxdepth 1 -type d -print 2>/dev/null | sort -r)

    if (( ${#backups[@]} == 0 )); then
        info "No Take Over backups found."
        pause
        return
    fi

    local i base tunnel stamp files size
    printf '%-4s %-28s %-17s %-8s %s\n' "#" "Tunnel / Backup" "Timestamp" "Files" "Size"
    printf '%-4s %-28s %-17s %-8s %s\n' "──" "────────────────────────────" "─────────────────" "────────" "────────"
    for i in "${!backups[@]}"; do
        d="${backups[$i]}"
        base="$(basename "${d}")"
        stamp="${base##*-}"
        # timestamp consists of YYYYMMDD-HHMMSS, so recover the last two dash-separated parts
        if [[ "${base}" =~ ^(.+)-([0-9]{8})-([0-9]{6})$ ]]; then
            tunnel="${BASH_REMATCH[1]}"
            stamp="${BASH_REMATCH[2]} ${BASH_REMATCH[3]}"
            stamp="${stamp:0:4}-${stamp:4:2}-${stamp:6:2} ${stamp:9:2}:${stamp:11:2}:${stamp:13:2}"
        else
            tunnel="${base}"
        fi
        files="$(find "${d}" -maxdepth 1 -type f 2>/dev/null | wc -l)"
        size="$(du -sh "${d}" 2>/dev/null | awk '{print $1}')"
        printf '%-4s %-28s %-17s %-8s %s\n' "$((i+1))" "${tunnel}" "${stamp}" "${files}" "${size:-?}"
    done

    echo
    echo "Enter backup number to show its contents."
    echo "B = Back    E = Exit"

    local choice selected
    read -r -p "Selection: " choice
    case "${choice}" in
        [bB]|0|"") return ;;
        [eE]) clear_screen; echo "Bye."; exit 0 ;;
    esac

    [[ "${choice}" =~ ^[0-9]+$ ]] || { error "Invalid selection."; sleep 1; return; }
    (( choice >= 1 && choice <= ${#backups[@]} )) || { error "Invalid selection."; sleep 1; return; }

    selected="${backups[$((choice-1))]}"
    banner
    section "BACKUP DETAILS"
    printf '%-30s %s\n' "Backup:" "${selected}"
    printf '%-30s %s\n' "Size:" "$(du -sh "${selected}" 2>/dev/null | awk '{print $1}')"
    echo
    echo "Preserved files:"
    find "${selected}" -maxdepth 1 -type f -printf '  • %f\n' 2>/dev/null | sort
    echo
    info "Backups are read-only from this menu; nothing is restored or deleted here."
    echo
    echo "B = Back to backup list    E = Exit"

    local detail_choice
    read -r -p "Selection: " detail_choice
    case "${detail_choice}" in
        [eE]) clear_screen; echo "Bye."; exit 0 ;;
        [bB]|0|"") show_takeover_backups; return ;;
        *) error "Invalid selection."; sleep 1; show_takeover_backups; return ;;
    esac
}

takeover_imported_tunnel() {
    banner
    section "TAKE OVER IMPORTED TUNNEL"

    echo "Converts a previously imported read-only tunnel into a manager-owned tunnel."
    echo "The manager validates the existing setup and creates a backup before taking ownership."
    echo "After takeover, the tunnel can be managed with the normal S2S Manager functions."
    echo

    select_tunnel || return

    local name="${SELECTED_TUNNEL}"
    load_tunnel "${name}" || return

    if [[ "${MANAGEMENT}" != "IMPORTED" ]]; then
        warn "Tunnel '${name}' is already manager-owned or only defined."
        echo "Take Over is only available for IMPORTED / READ-ONLY tunnels."
        pause
        return
    fi

    local old_conn="${SOURCE_CONN_NAME}"
    local old_swan="${SOURCE_SWAN_FILE}"
    local old_vti_script="${SOURCE_VTI_SCRIPT}"
    local old_service="${SOURCE_SERVICE}"
    local old_forced_natt="${SOURCE_FORCED_NATT:-0}"
    local source_psk

    takeover_analyze_old_service "${old_service}"

    source_psk="$(extract_psk_from_swan_file "${old_swan}" 2>/dev/null || true)"
    if [[ -z "${source_psk}" ]]; then
        error "The PSK could not be read from the original strongSwan configuration."
        echo "Take Over has been cancelled."
        pause
        return
    fi

    section "TAKE OVER PREVIEW"

    printf '%-30s %s\n' "Tunnel:" "${NAME}"
    printf '%-30s %s\n' "Current management:" "IMPORTED / READ-ONLY"
    printf '%-30s %s\n' "Current connection:" "${old_conn}"
    printf '%-30s %s\n' "New manager connection:" "${MANAGED_PREFIX}-${NAME}"
    printf '%-30s %s\n' "VTI interface:" "${VTI_INTERFACE}"
    printf '%-30s %s\n' "Tunnel network:" "${VTI_NETWORK}"
    printf '%-30s %s\n' "Authentication ID:" "${AUTH_ID}"
    printf '%-30s %s\n' "PSK:" "reuse existing PSK from source config"
    echo

    echo "Existing external files:"
    printf '  strongSwan:  %s\n' "${old_swan:-not detected}"
    printf '  VTI script:  %s\n' "${old_vti_script:-not detected}"
    printf '  systemd:     %s\n' "${old_service:-not detected}"
    if [[ -n "${old_service}" ]]; then
        printf '  service state: %s\n' "${TAKEOVER_OLD_SERVICE_NOTE}"
    fi
    echo

    echo "Manager files that will replace them:"
    printf '  strongSwan:  %s\n' "$(managed_swan_file "${name}")"
    printf '  VTI script:  %s\n' "$(managed_vti_script "${name}")"
    printf '  systemd:     %s\n' "$(managed_service_file "${name}")"
    echo

    echo "Manager IPsec defaults that will become active:"
    echo "  • Forced NAT-T / ESP-in-UDP: Enabled"
    echo "  • IKE hard lifetime:         28800s (8h)"
    echo "  • ESP hard lifetime:         3600s (1h)"
    echo

    if [[ "${old_forced_natt}" != "1" ]]; then
        warn "The current imported tunnel uses native ESP."
        echo "Take Over will switch this tunnel to forced NAT-T / UDP 4500."
        echo "The UniFi configuration itself does not need to be changed."
        echo
    fi

    echo "SAFETY / BACKUP:"
    echo "  • Take Over modifies an existing IPsec/VTI installation."
    echo "  • Use at your own risk; console or provider access is recommended."
    echo "  • The manager creates a timestamped backup BEFORE changing the source files."
    echo "  • Backups are retained under ${BACKUP_DIR} and are NOT auto-deleted."
    echo "  • Automatic rollback uses that backup if a later Take Over step fails."
    echo "  • A backup reduces risk, but cannot guarantee recovery from every external"
    echo "    network, firewall, systemd or host-specific configuration."
    echo
    echo "Take Over will perform these exact 12 steps:"
    echo "  1. Back up the original files."
    echo "  2. Refresh the manager PSK from the original strongSwan config."
    echo "  3. Build a staged manager strongSwan config."
    echo "  4. Validate the staged manager connection while the old tunnel stays up."
    echo "  5. Write the manager VTI script."
    echo "  6. Write the manager systemd service."
    echo "  7. Disable the old VTI service and safely clear its runtime state when possible."
    echo "  8. Activate manager files and retire the old external files."
    echo "  9. Reload and verify the manager strongSwan connection."
    echo " 10. Enable the manager VTI service."
    echo " 11. Terminate the old SA and wait up to 60 seconds for UniFi to reconnect."
    echo " 12. Test VTI connectivity."
    echo
    echo "IMPORTANT:"
    echo "The old working IPsec SA is NOT terminated unless the new manager"
    echo "connection has first been successfully loaded and verified."
    echo
    echo "If a later step fails, automatic rollback restores the original files"
    echo "and the imported READ-ONLY manager state."
    echo
    warn "Traffic is only interrupted during step 11."
    echo

    read -r -p "Type TAKEOVER to continue: " confirm
    [[ "${confirm^^}" == "TAKEOVER" ]] || return

    local timestamp backup_root stage_file
    timestamp="$(date +%Y%m%d-%H%M%S)"
    backup_root="${BACKUP_DIR}/${name}-${timestamp}"
    stage_file="${backup_root}/manager-staged.conf"

    section "TAKING OVER TUNNEL"

    printf '[1/12] Backing up original files... '
    mkdir -p "${backup_root}"
    chmod 700 "${backup_root}"
    takeover_backup_file "${old_swan}" "${backup_root}" "strongswan.conf"
    takeover_backup_file "${old_vti_script}" "${backup_root}" "vti-script"
    if [[ -n "${old_service}" ]]; then
        takeover_backup_file "${SYSTEMD_DIR}/${old_service}" "${backup_root}" "systemd-service"
    fi
    printf '%b\n' "${C_GREEN}OK${C_RESET}"

    printf '[2/12] Refreshing imported PSK from source... '
    save_psk "${name}" "${source_psk}"
    printf '%b\n' "${C_GREEN}OK${C_RESET}"

    printf '[3/12] Building staged manager strongSwan config... '
    if render_strongswan_config_to_file "${name}" "${stage_file}"; then
        printf '%b\n' "${C_GREEN}OK${C_RESET}"
    else
        printf '%b\n' "${C_RED}FAILED${C_RESET}"
        error "Could not render the staged manager configuration."
        pause
        return 1
    fi

    printf '[4/12] Validating staged manager connection... '
    if swanctl_clean swanctl --load-conns --file "${stage_file}" \
        >/tmp/s2s-manager-takeover-stage-load.log 2>&1; then
        :
    fi

    local takeover_conns
    takeover_conns="$(swanctl_clean swanctl --list-conns 2>/dev/null || true)"
    if grep -qE "^${MANAGED_PREFIX}-${name}:" <<< "${takeover_conns}"; then
        printf '%b\n' "${C_GREEN}OK${C_RESET}"
    else
        printf '%b\n' "${C_RED}FAILED${C_RESET}"
        error "The staged manager connection was not loaded."
        echo
        cat /tmp/s2s-manager-takeover-stage-load.log 2>/dev/null || true
        echo
        info "The current working tunnel has NOT been terminated."
        info "The staged file was preserved for analysis:"
        echo "  ${stage_file}"
        # Restore the normal loaded connection set. Established SAs are left intact.
        swanctl_clean swanctl --load-all >/tmp/s2s-manager-takeover-stage-restore.log 2>&1 || true
        pause
        return 1
    fi

    # Restore the normal active configuration set before changing any files.
    swanctl_clean swanctl --load-all >/tmp/s2s-manager-takeover-stage-restore.log 2>&1 || true
    takeover_conns="$(swanctl_clean swanctl --list-conns 2>/dev/null || true)"
    if ! grep -qE "^${old_conn}:" <<< "${takeover_conns}"; then
        error "Could not restore the original loaded connection after staged validation."
        echo "The active IKE SA was not intentionally terminated."
        pause
        return 1
    fi

    printf '[5/12] Writing manager VTI script... '
    if render_vti_script "${name}"; then
        printf '%b\n' "${C_GREEN}OK${C_RESET}"
    else
        printf '%b\n' "${C_RED}FAILED${C_RESET}"
        pause
        return 1
    fi

    printf '[6/12] Writing manager systemd service... '
    if render_systemd_service "${name}"; then
        printf '%b\n' "${C_GREEN}OK${C_RESET}"
    else
        printf '%b\n' "${C_RED}FAILED${C_RESET}"
        rm -f "$(managed_vti_script "${name}")"
        pause
        return 1
    fi

    printf '[7/12] Retiring old VTI service safely... '
    if [[ -n "${old_service}" ]]; then
        systemctl disable "${old_service}" >/tmp/s2s-manager-takeover-disable-old.log 2>&1 || true

        if [[ "${TAKEOVER_OLD_SERVICE_SAFE_STOP}" == "1" ]]; then
            # No ExecStop/ExecStopPost hooks were found. For a oneshot service
            # with RemainAfterExit this clears only systemd's stale active state.
            systemctl stop "${old_service}" >/tmp/s2s-manager-takeover-stop-old.log 2>&1 || true
        elif [[ "${TAKEOVER_OLD_SERVICE_ACTIVE}" == "1" &&
                "${TAKEOVER_OLD_SERVICE_STOP_HOOKS}" == "1" ]]; then
            # Do not execute unknown external teardown hooks automatically.
            printf '%bWARNING%b\n' "${C_YELLOW}" "${C_RESET}"
            warn "Old service has ExecStop/ExecStopPost hooks and was not stopped automatically."
            printf '       '
        fi
    fi
    printf '%b\n' "${C_GREEN}OK${C_RESET}"

    printf '[8/12] Activating manager files / retiring old files... '
    cp -a "${stage_file}" "$(managed_swan_file "${name}")"
    chmod 600 "$(managed_swan_file "${name}")"
    [[ -n "${old_swan}" ]] && rm -f "${old_swan}"
    [[ -n "${old_vti_script}" ]] && rm -f "${old_vti_script}"
    if [[ -n "${old_service}" ]]; then
        rm -f "${SYSTEMD_DIR}/${old_service}"
    fi
    systemctl daemon-reload
    printf '%b\n' "${C_GREEN}OK${C_RESET}"

    printf '[9/12] Reloading / verifying manager strongSwan connection... '
    swanctl_clean swanctl --load-all >/tmp/s2s-manager-takeover-load.log 2>&1 || true

    takeover_conns="$(swanctl_clean swanctl --list-conns 2>/dev/null || true)"
    if grep -qE "^${MANAGED_PREFIX}-${name}:" <<< "${takeover_conns}"; then
        printf '%b\n' "${C_GREEN}OK${C_RESET}"
    else
        printf '%b\n' "${C_RED}FAILED${C_RESET}"
        error "The manager connection is not loaded. The working SA has NOT been terminated."
        echo
        cat /tmp/s2s-manager-takeover-load.log 2>/dev/null || true
        takeover_rollback "${name}" "${old_conn}" "${old_swan}" "${old_vti_script}" "${old_service}" "${backup_root}"
        pause
        return 1
    fi

    printf '[10/12] Enabling manager VTI service... '
    if systemctl enable --now "$(managed_service_name "${name}")" \
        >/tmp/s2s-manager-takeover-manager-service.log 2>&1; then
        printf '%b\n' "${C_GREEN}OK${C_RESET}"
    else
        printf '%b\n' "${C_RED}FAILED${C_RESET}"
        cat /tmp/s2s-manager-takeover-manager-service.log
        takeover_rollback "${name}" "${old_conn}" "${old_swan}" "${old_vti_script}" "${old_service}" "${backup_root}"
        pause
        return 1
    fi

    printf '[11/12] Switching IPsec connection... '
    swanctl_clean swanctl --terminate --ike "${old_conn}" \
        >/tmp/s2s-manager-takeover-terminate-old.log 2>&1 || true

    TAKEOVER_RECONNECT_SECONDS=""
    if takeover_wait_for_connection "${name}" 60; then
        printf '%bOK%b (%ss)\n' "${C_GREEN}" "${C_RESET}" "${TAKEOVER_RECONNECT_SECONDS}"
    else
        printf '%bFAILED%b\n' "${C_RED}" "${C_RESET}"
        error "UniFi did not reconnect to the manager-owned connection within 60 seconds."
        takeover_rollback "${name}" "${old_conn}" "${old_swan}" "${old_vti_script}" "${old_service}" "${backup_root}"
        pause
        return 1
    fi

    sleep 2

    printf '[12/12] Testing VTI connectivity... '
    if ping -c 3 -W 2 "${UNIFI_VTI_IP}" >/tmp/s2s-manager-takeover-ping.log 2>&1; then
        printf '%b\n' "${C_GREEN}OK${C_RESET}"
    elif grep -Eq '[1-9][0-9]* received' /tmp/s2s-manager-takeover-ping.log; then
        printf '%b\n' "${C_YELLOW}PARTIAL${C_RESET}"
        warn "The tunnel is established but the immediate VTI ping had packet loss."
    else
        printf '%b\n' "${C_RED}FAILED${C_RESET}"
        error "The manager-owned IPsec SA is established, but VTI connectivity failed."
        takeover_rollback "${name}" "${old_conn}" "${old_swan}" "${old_vti_script}" "${old_service}" "${backup_root}"
        pause
        return 1
    fi

    save_tunnel \
        "${NAME}" "${PUBLIC_IP}" "${AUTH_ID}" "${VTI_INTERFACE}" "${VTI_KEY}" \
        "${VTI_NETWORK}" "${DEBIAN_VTI_IP}" "${UNIFI_VTI_IP}" "1" \
        "${PEER_MODE}" "${PEER_ADDRESS}" "${DISPLAY_NAME}" "${PEER_TYPE}"

    cat >> "$(tunnel_config_file "${name}")" <<EOF
TAKEOVER_BACKUP_DIR=$(printf '%q' "${backup_root}")
EOF
    chmod 600 "$(tunnel_config_file "${name}")"

    echo
    ok "Take Over completed successfully."
    printf '%-30s %s\n' "Management:" "MANAGED"
    printf '%-30s %s\n' "Connection:" "CONNECTED"
    printf '%-30s %s\n' "Reconnect time:" "${TAKEOVER_RECONNECT_SECONDS}s"
    printf '%-30s %s\n' "Backup:" "${backup_root}"
    echo
    info "The original PSK was retained."
    info "The original files are preserved in the Take Over backup."
    info "Take Over backups are retained until you remove them manually."
    pause
}


# ==============================================================================
# Create / edit state
# ==============================================================================

add_tunnel_definition() {
    banner
    section "ADD SITE-TO-SITE TUNNEL"

    echo "Creates a new managed S2S tunnel definition step by step."
    echo "You choose the peer type, endpoint, transfer network, remote networks and PSK."
    echo "The definition can be saved first and installed on Debian afterwards."
    echo

    local detected_ip
    detected_ip="$(detect_public_ipv4)"
    [[ -n "${detected_ip}" ]] || detected_ip="0.0.0.0"

    local tunnel_number suggested_name
    tunnel_number=$(( $(tunnel_count) + 1 ))
    suggested_name="home"
    (( tunnel_number > 1 )) && suggested_name="s2s-${tunnel_number}"

    section "STEP 1/8  Tunnel Display Name"
    prompt_display_name "${suggested_name}"
    local display_name="${PROMPT_RESULT}"
    local name
    name="$(next_internal_name_for_display "${display_name}")"
    echo
    printf '%-28s %s\n' "Display name:" "${display_name}"
    printf '%-28s %s\n' "Internal name:" "${name}"
    if [[ "${name}" != "$(display_to_internal_base "${display_name}")" ]]; then
        info "Internal name adjusted automatically to avoid a technical name/file collision."
    fi

    section "STEP 2/8  Peer Type"
    echo "Choose the remote Site-to-Site peer type."
    echo
    echo "  [1] UniFi Gateway"
    echo "      Create a tunnel to a UniFi gateway."
    echo
    echo "  [2] Debian / strongSwan"
    echo "      Create a tunnel to another Debian server running strongSwan."
    echo "      A mirrored peer bundle including the PSK can be created afterwards."
    echo
    echo "  [B] Back"
    echo "  [E] Exit"
    echo
    echo "Press ENTER to use option 1."
    local peer_type_choice peer_type
    while :; do
        read -r -p "Selection [1]: " peer_type_choice
        peer_type_choice="${peer_type_choice:-1}"
        case "${peer_type_choice}" in
            1) peer_type="unifi"; break ;;
            2) peer_type="debian"; break ;;
            b|B|0) return ;;
            e|E) clear_screen; echo "Bye."; exit 0 ;;
            *) validation_error_block "INVALID SELECTION" "Choose 1 or 2." ;;
        esac
    done

    section "STEP 3/8  Peer Endpoint"
    prompt_peer_endpoint "${peer_type}" || return
    local peer_mode="${PROMPT_PEER_MODE}"
    local peer_address="${PROMPT_PEER_ADDRESS}"

    section "STEP 4/8  Debian Public IP"
    prompt_public_ip "${detected_ip}" "${peer_type}"
    local public_ip="${PROMPT_RESULT}"
    local install_topology_conflict=0
    local install_topology_conflict_detail=""

    # Warn immediately if this definition uses a wildcard VTI that cannot later
    # be installed alongside an existing wildcard VTI on the same local endpoint.
    if [[ "${peer_mode}" == "dynamic" ]]; then
        local wildcard_conflict=""
        if find_wildcard_vti_conflict "${public_ip}" ""; then
            wildcard_conflict="${VTI_TOPOLOGY_CONFLICT_INTERFACE}"
        fi
        if [[ -n "${wildcard_conflict}" ]]; then
            install_topology_conflict=1
            install_topology_conflict_detail="wildcard VTI conflict with ${wildcard_conflict}"
            echo
            printf '%b\n' "${C_BOLD}${C_RED}──────────────────────────────────────────────────────────────${C_RESET}"
            printf '%b\n' "${C_BOLD}${C_RED}  ✗ DYNAMIC ENDPOINT CONFLICT${C_RESET}"
            printf '%b\n' "${C_BOLD}${C_RED}──────────────────────────────────────────────────────────────${C_RESET}"
            printf '%b%s%b\n' "${C_RED}" "Another wildcard VTI already uses Debian public IP ${public_ip}." "${C_RESET}"
            printf '%b%s%b\n' "${C_RED}" "Existing VTI: ${wildcard_conflict}" "${C_RESET}"
            echo
            printf '%b%s%b\n' "${C_BOLD}${C_RED}" "You CAN save this tunnel definition, but you CANNOT activate/install it" "${C_RESET}"
            printf '%b%s%b\n' "${C_BOLD}${C_RED}" "while both tunnels use Dynamic / unknown on the same Debian public IP." "${C_RESET}"
            printf '%b\n' "${C_BOLD}${C_RED}──────────────────────────────────────────────────────────────${C_RESET}"
            echo
        fi
    fi

    # For Static IPv4 / Dynamic DNS, compare the effective IPv4 endpoint pair
    # against already existing VTIs. DNS names are compared by resolved IPv4.
    if [[ "${peer_mode}" == "static" || "${peer_mode}" == "dns" ]]; then
        local effective_peer_ip=""
        if [[ "${peer_mode}" == "static" ]]; then
            effective_peer_ip="${peer_address}"
        else
            PEER_RESOLVED_IP=""
            PEER_RESOLVE_MULTIPLE=""
            if resolve_peer_hostname "${peer_address}"; then
                effective_peer_ip="${PEER_RESOLVED_IP}"
            fi
        fi

        if [[ -n "${effective_peer_ip}" ]] &&
           find_specific_vti_conflict "${public_ip}" "${effective_peer_ip}" ""; then
            local specific_conflict="${VTI_TOPOLOGY_CONFLICT_INTERFACE}"
            local existing_tunnel=""
            local candidate
            while IFS= read -r candidate; do
                [[ -n "${candidate}" ]] || continue
                load_tunnel "${candidate}" >/dev/null 2>&1 || continue
                if [[ "${VTI_INTERFACE}" == "${specific_conflict}" ]]; then
                    existing_tunnel="${candidate}"
                    break
                fi
            done < <(list_tunnel_names)

            install_topology_conflict=1
            install_topology_conflict_detail="endpoint pair conflict with ${specific_conflict}"

            echo
            printf '%b\n' "${C_BOLD}${C_RED}──────────────────────────────────────────────────────────────${C_RESET}"
            printf '%b\n' "${C_BOLD}${C_RED}  ✗ VTI ENDPOINT CONFLICT${C_RESET}"
            printf '%b\n' "${C_BOLD}${C_RED}──────────────────────────────────────────────────────────────${C_RESET}"
            printf '%b%s%b\n' "${C_RED}" "Another VTI already uses this endpoint pair." "${C_RESET}"
            echo
            printf '%b%-20s %s%b\n' "${C_RED}" "Debian public IP:" "${public_ip}" "${C_RESET}"
            printf '%b%-20s %s%b\n' "${C_RED}" "Peer endpoint:" "${effective_peer_ip}" "${C_RESET}"
            [[ -n "${existing_tunnel}" ]] && printf '%b%-20s %s%b\n' "${C_RED}" "Existing tunnel:" "${existing_tunnel}" "${C_RESET}"
            printf '%b%-20s %s%b\n' "${C_RED}" "Existing VTI:" "${specific_conflict}" "${C_RESET}"
            echo
            printf '%b%s%b\n' "${C_BOLD}${C_RED}" "You CAN save this tunnel definition, but you CANNOT activate/install it" "${C_RESET}"
            printf '%b%s%b\n' "${C_BOLD}${C_RED}" "while another VTI uses the same local and remote endpoint addresses." "${C_RESET}"
            printf '%b\n' "${C_BOLD}${C_RED}──────────────────────────────────────────────────────────────${C_RESET}"
            echo
        fi
    fi


    section "STEP 5/8  Site-to-Site Tunnel Network"
    local suggested_network
    suggested_network="$(next_vti_network)"
    prompt_tunnel_network "${suggested_network}" "${peer_type}" || return
    local network="${PROMPT_NETWORK}"
    local debian_ip="${PROMPT_DEBIAN_IP}"
    local unifi_ip="${PROMPT_UNIFI_IP}"

    local auth_id
    section "STEP 6/8  Peer Authentication ID"
    if [[ "${peer_type}" == "debian" ]]; then
        auth_id="$(resolve_tunnel_peer_ipv4 "${peer_mode}" "${peer_address}" 2>/dev/null || true)"
        if [[ -z "${auth_id}" ]]; then
            validation_error_block "PEER AUTHENTICATION ID UNAVAILABLE" "The Debian peer endpoint must currently resolve to exactly one IPv4 address" "so its IKE Authentication ID can be configured." "Peer: ${peer_address}"
            return
        fi
        echo "For Debian / strongSwan peers, the remote server identifies itself"
        echo "with its public IPv4 address. The manager sets this automatically."
        echo
        printf '%-28s %s\n' "Authentication ID:" "${auth_id}"
        validation_success "Debian peer Authentication ID set automatically"
    else
        prompt_auth_id "unifi-${name}"
        auth_id="${PROMPT_RESULT}"
    fi

    section "STEP 7/8  Remote Networks"
    prompt_remote_networks "${network}" "${peer_type}" || return
    local -a routes=("${PROMPT_ROUTES[@]:-}")

    section "STEP 8/8  Pre-Shared Key"
    prompt_psk "${peer_type}" || return
    local psk="${PROMPT_PSK}"

    local idx interface key
    idx="$(next_interface_index)"
    interface="ipsec${idx}"
    key=$((DEFAULT_VTI_KEY + idx))

    section "CONFIGURATION SUMMARY"
    printf '%-28s %s\n' "Display name:" "${display_name}"
    printf '%-28s %s\n' "Internal name:" "${name}"
    printf '%-28s %s\n' "Peer type:" "$([[ "${peer_type}" == "debian" ]] && echo 'Debian / strongSwan' || echo 'UniFi Gateway')"
    printf '%-28s %s\n' "Local Debian public IP:" "${public_ip}"
    printf '%-28s %s\n' "Authentication ID:" "${auth_id}"
    printf '%-28s %s\n' "Peer mode:" "$(peer_mode_label "${peer_mode}")"
    [[ "${peer_mode}" != "dynamic" ]] && printf '%-28s %s\n' "Peer address:" "${peer_address}"
    printf '%-28s %s\n' "VTI interface:" "${interface}"
    printf '%-28s %s\n' "VTI key / mark:" "${key}"
    printf '%-28s %s\n' "Tunnel network:" "${network}"
    printf '%-28s %s\n' "Local Debian VTI IP:" "${debian_ip}"
    if [[ "${peer_type}" == "debian" ]]; then
        printf '%-28s %s\n' "Remote Debian VTI IP:" "${unifi_ip}"
    else
        printf '%-28s %s\n' "UniFi VTI IP:" "${unifi_ip}"
    fi

    echo
    if (( install_topology_conflict == 1 )); then
        validation_error "VTI topology conflict detected - definition cannot currently be installed"
        printf '%-28s %s\n' "Installation status:" "CANNOT ACTIVATE"
        printf '%-28s %s\n' "Reason:" "${install_topology_conflict_detail}"
    else
        ok "Conflict validation passed"
    fi
    printf '%-28s %s\n' "Interface allocation:" "${interface} (free)"
    printf '%-28s %s\n' "VTI key / mark allocation:" "${key} (free)"
    echo
    echo "Remote networks:"
    local nonempty_routes=0 r
    for r in "${routes[@]:-}"; do [[ -n "${r}" ]] && ((nonempty_routes += 1)); done
    if (( nonempty_routes == 0 )); then echo "  None"; else for r in "${routes[@]:-}"; do [[ -n "${r}" ]] && printf '  • %s\n' "${r}"; done; fi

    echo
    confirm_yes_no "Save tunnel definition?" "N" || return
    save_tunnel "${name}" "${public_ip}" "${auth_id}" "${interface}" "${key}" \
        "${network}" "${debian_ip}" "${unifi_ip}" "0" "${peer_mode}" "${peer_address}" "${display_name}" "${peer_type}"
    write_routes "${name}" "${routes[@]:-}"
    save_psk "${name}" "${psk}"
    ok "Tunnel definition saved."

    if [[ "${peer_type}" == "debian" ]]; then
        echo
        info "After saving, use 'Create Debian peer bundle' to create the mirrored peer configuration including the same PSK."
    fi

    echo
    if confirm_yes_no "Install this tunnel on Debian now?" "N"; then
        if ensure_ipsec_ready_for_action; then
            install_tunnel_system_config "${name}"
            return
        fi
        info "The tunnel definition remains saved and can be installed later."
    fi
    pause
}

add_remote_network() {
    banner
    section "ADD REMOTE NETWORK"

    echo "Adds another network that should be reachable through an existing S2S tunnel."
    echo "The manager checks the network for conflicts before saving it."
    echo "For an installed tunnel, re-apply the configuration afterwards to activate the route."
    echo
    select_tunnel || return

    local name="${SELECTED_TUNNEL}"
    load_tunnel "${name}" || return

    if [[ "${MANAGEMENT}" == "IMPORTED" ]]; then
        imported_readonly_notice "${name}"
        pause
        return
    fi


    echo "Current remote networks:"
    local route count=0
    while read -r route; do
        [[ -z "${route}" ]] && continue
        printf '  • %s\n' "${route}"
        ((count += 1))
    done < <(read_routes "${name}")
    (( count == 0 )) && echo "  None"

    echo
    echo "Enter a CIDR network, e.g. 192.168.50.0/24"
    echo "Press ENTER or B to go back. E = Exit."
    echo

    local new_route
    while :; do
        read -r -p "New remote network: " new_route
        case "${new_route}" in
            ""|b|B|0) return ;;
            e|E) clear_screen; echo "Bye."; exit 0 ;;
        esac

        if ! valid_cidr "${new_route}"; then
            validation_error_block                 "INVALID CIDR NETWORK"                 "The entered value is not a valid IPv4 CIDR network:"                 "  ${new_route}"
            continue
        fi

        if [[ "${new_route}" == "0.0.0.0/0" ]]; then
            validation_error_block                 "REMOTE NETWORK NOT ALLOWED"                 "0.0.0.0/0 is not allowed as a remote network."                 "Use explicit remote LAN/VLAN networks instead."
            continue
        fi

        if ! cidr_is_exact_network "${new_route}"; then
            validation_error_block                 "HOST ADDRESS ENTERED"                 "${new_route} is not the network base address."                 "Use instead:  $(cidr_normalized "${new_route}")"
            continue
        fi
        new_route="$(cidr_normalized "${new_route}")"

        if cidr_overlaps "${new_route}" "${VTI_NETWORK}"; then
            validation_error_block                 "NETWORK CONFLICT"                 "Remote network:  ${new_route}"                 "Tunnel network:  ${VTI_NETWORK}"                 "Reason:          remote network overlaps this tunnel's transfer network"
            continue
        fi

        local existing_route same_tunnel_conflict=0
        while read -r existing_route; do
            [[ -z "${existing_route}" ]] && continue
            if cidr_overlaps "${new_route}" "${existing_route}"; then
                validation_error_block                     "NETWORK CONFLICT"                     "Requested:       ${new_route}"                     "Conflicts with:  ${existing_route}"                     "Reason:          overlaps an existing remote network on this tunnel"
                same_tunnel_conflict=1
                break
            fi
        done < <(read_routes "${name}")
        (( same_tunnel_conflict == 1 )) && { echo; continue; }

        if check_network_conflict "${new_route}" "${name}" "${VTI_INTERFACE}"; then
            show_network_conflict "${new_route}"
            echo
            continue
        fi

        validation_success "Network available: ${new_route}"
        confirm_yes_no "Add ${new_route}?" "N" || return

        printf '%s\n' "${new_route}" >> "$(tunnel_route_file "${name}")"
        chmod 600 "$(tunnel_route_file "${name}")"

        ok "Remote network added to manager state."
        printf '  State file: %s\n' "$(tunnel_route_file "${name}")"

        if tunnel_is_installed "${name}"; then
            echo
            reapply_installed_tunnel "${name}" || {
                error "State was updated, but re-applying the installed tunnel failed."
                pause
                return 1
            }
        else
            info "Tunnel is only defined, so no live system configuration needs updating."
        fi

        pause
        return
    done
}

remove_remote_network() {
    banner
    section "REMOVE REMOTE NETWORK"

    echo "Removes a configured remote network from an existing S2S tunnel."
    echo "This changes the saved tunnel definition but does not delete the tunnel itself."
    echo "For an installed tunnel, re-apply the configuration afterwards to remove the active route."
    echo
    select_tunnel || return

    local name="${SELECTED_TUNNEL}"
    load_tunnel "${name}" || return

    if [[ "${MANAGEMENT}" == "IMPORTED" ]]; then
        imported_readonly_notice "${name}"
        pause
        return
    fi


    local -a routes=()
    local route
    while read -r route; do
        [[ -n "${route}" ]] && routes+=("${route}")
    done < <(read_routes "${name}")

    (( ${#routes[@]} > 0 )) || { warn "No remote networks configured."; pause; return; }

    local i selection
    for i in "${!routes[@]}"; do
        printf '  [%d] %s\n' "$((i + 1))" "${routes[$i]}"
    done
    echo
    echo "Enter network number and press ENTER."
    echo "B = Back    E = Exit"
    echo
    read -r -p "Selection: " selection

    case "${selection}" in
        ""|b|B|0) return ;;
        e|E) clear_screen; echo "Bye."; exit 0 ;;
    esac
    [[ "${selection}" =~ ^[0-9]+$ ]] || return
    (( selection >= 1 && selection <= ${#routes[@]} )) || return

    local remove="${routes[$((selection - 1))]}"
    confirm_yes_no "Remove ${remove}?" "N" || return

    local file
    file="$(tunnel_route_file "${name}")"
    grep -Fxv "${remove}" "${file}" > "${file}.tmp" || true
    mv "${file}.tmp" "${file}"
    chmod 600 "${file}"

    ok "Remote network removed from manager state."
    printf '  State file: %s\n' "$(tunnel_route_file "${name}")"

    if tunnel_is_installed "${name}"; then
        # Reload the tunnel state because tunnel_is_installed() may source it.
        load_tunnel "${name}" || return 1

        # Remove the live route immediately if present, then regenerate from state.
        ip route del "${remove}" dev "${VTI_INTERFACE}" table 220 >/dev/null 2>&1 || true

        echo
        reapply_installed_tunnel "${name}" || {
            error "State was updated, but re-applying the installed tunnel failed."
            pause
            return 1
        }
    else
        info "Tunnel is only defined, so no live system configuration needs updating."
    fi

    pause
}

delete_tunnel_completely() {
    banner
    section "DELETE TUNNEL COMPLETELY"

    echo "Permanently removes the selected tunnel from the S2S Manager."
    echo "If installed, its manager-owned Debian configuration is removed as well."
    echo "The tunnel definition, remote-network state and stored PSK are then deleted."
    echo "Use a tunnel backup first if you may need the configuration again."
    echo
    select_tunnel || return

    local name="${SELECTED_TUNNEL}"
    load_tunnel "${name}" || return

    echo "Tunnel:                      ${name}"
    if [[ "${MANAGEMENT}" == "IMPORTED" ]]; then
        printf '%-28s %s\n' "Management:" "IMPORTED / READ-ONLY"
        echo
        warn "This tunnel is imported and READ-ONLY."
        echo "Only the S2S Manager state and copied PSK will be deleted."
        echo "The external strongSwan, VTI and systemd configuration will NOT be changed."
        echo
        read -r -p "Type DELETE to confirm: " confirm
        [[ "${confirm}" == "DELETE" ]] || return

        rm -f \
            "$(tunnel_config_file "${name}")" \
            "$(tunnel_route_file "${name}")" \
            "$(tunnel_secret_file "${name}")"

        ok "Imported tunnel removed from S2S Manager state."
        pause
        return
    fi

    local was_installed=0
    tunnel_is_installed "${name}" && was_installed=1
    # tunnel_is_installed() may load state for another check, so restore this tunnel.
    load_tunnel "${name}" || return

    if (( was_installed == 1 )); then
        printf '%-28s %s\n' "Management:" "MANAGED / INSTALLED"
        echo
        echo "This will completely remove the tunnel from Debian and the manager."
        echo
        echo "The following will be removed:"
        echo "  • active strongSwan configuration"
        echo "  • VTI interface ${VTI_INTERFACE}"
        echo "  • systemd VTI service"
        echo "  • table 220 routes created by the VTI script"
        echo "  • tunnel definition and remote-network state"
        echo "  • stored PSK"
    else
        printf '%-28s %s\n' "Management:" "DEFINED / MANAGED"
        echo
        echo "This tunnel is not installed on Debian."
        echo "The tunnel definition, remote-network state and stored PSK will be removed."
    fi

    echo
    read -r -p "Type DELETE to confirm: " confirm
    [[ "${confirm}" == "DELETE" ]] || return

    if (( was_installed == 1 )); then
        echo
        section "REMOVING INSTALLED TUNNEL"

        printf '[1/5] Terminating active IPsec connection... '
        swanctl --terminate --ike "${MANAGED_PREFIX}-${name}" >/dev/null 2>&1 || true
        printf '%b\n' "${C_GREEN}OK${C_RESET}"

        printf '[2/5] Stopping / disabling VTI service... '
        systemctl disable --now "$(managed_service_name "${name}")" >/dev/null 2>&1 || true
        printf '%b\n' "${C_GREEN}OK${C_RESET}"

        printf '[3/5] Removing VTI interface and manager system files... '
        ip link del "${VTI_INTERFACE}" >/dev/null 2>&1 || true
        rm -f \
            "$(managed_swan_file "${name}")" \
            "$(managed_vti_script "${name}")" \
            "$(managed_service_file "${name}")"
        printf '%b\n' "${C_GREEN}OK${C_RESET}"

        printf '[4/5] Reloading systemd / strongSwan... '
        systemctl daemon-reload
        swanctl_clean swanctl --load-all >/dev/null 2>&1 || true
        printf '%b\n' "${C_GREEN}OK${C_RESET}"

        printf '[5/5] Removing manager definition and PSK... '
    fi

    rm -f \
        "$(tunnel_config_file "${name}")" \
        "$(tunnel_route_file "${name}")" \
        "$(tunnel_secret_file "${name}")"

    if (( was_installed == 1 )); then
        printf '%b\n' "${C_GREEN}OK${C_RESET}"

        if (( $(installed_tunnel_count) == 0 )) && ufw_installed; then
            echo
            warn "No other managed S2S tunnels are installed."
            if confirm_yes_no "Remove shared S2S Manager UFW rules?" "Y"; then
                remove_managed_ufw_rules
                ok "Managed UFW rules removed."
            fi
        fi
        echo
        ok "Tunnel '${name}' completely removed."
    else
        ok "Tunnel definition and PSK deleted."
    fi

    pause
}

# ==============================================================================
# Configuration views
# ==============================================================================

tunnel_table220_route_state() {
    local network="$1" interface="$2" output route_interface line
    output="$(ip -4 route show table 220 "${network}" 2>/dev/null || true)"
    while IFS= read -r line; do
        [[ "${line%% *}" == "${network}" ]] || continue
        route_interface="$(awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' <<< "${line}")"
        if [[ "${route_interface}" == "${interface}" ]]; then
            printf 'PRESENT'
        else
            printf 'WRONG: %s' "${route_interface:-unknown}"
        fi
        return 0
    done <<< "${output}"
    printf 'MISSING'
}

print_tunnel_route_state_cell() {
    local state="$1" width="$2"
    case "${state}" in
        PRESENT) print_table_cell "${state}" "${width}" "${C_GREEN}${C_BOLD}" "${C_RESET}" ;;
        MISSING|WRONG:*) print_table_cell "${state}" "${width}" "${C_RED}${C_BOLD}" "${C_RESET}" ;;
        *) print_table_cell "${state}" "${width}" ;;
    esac
}

show_all_tunnel_networks() {
    local name display interface transfer local_vti remote_vti connection actual_state route route_state
    local name_width=24 interface_width=10 connection_width=16 vti_width=18
    local type_width=10 network_width=22 route_width=18 gap="  " count=0

    banner
    section "ALL TUNNEL NETWORKS"
    echo "Shows every configured S2S transfer and remote network together with"
    echo "its expected VTI interface and current route state in table 220."
    echo "This overview is read-only and does not add, repair or remove routes."
    echo

    print_table_cell "Tunnel" "${name_width}"; printf '%s' "${gap}"
    print_table_cell "Interface" "${interface_width}"; printf '%s' "${gap}"
    print_table_cell "Connection" "${connection_width}"; printf '%s' "${gap}"
    print_table_cell "Local VTI" "${vti_width}"; printf '%s' "${gap}"
    print_table_cell "Remote VTI" "${vti_width}"; printf '\n'
    table_divider_segment "${name_width}"; printf '%s' "${gap}"
    table_divider_segment "${interface_width}"; printf '%s' "${gap}"
    table_divider_segment "${connection_width}"; printf '%s' "${gap}"
    table_divider_segment "${vti_width}"; printf '%s' "${gap}"
    table_divider_segment "${vti_width}"; printf '\n'

    while read -r name; do
        [[ -n "${name}" ]] || continue
        load_tunnel "${name}" || continue
        display="${DISPLAY_NAME:-${NAME}}"
        interface="${VTI_INTERFACE}"
        transfer="${VTI_NETWORK}"
        local_vti="${DEBIAN_VTI_IP}"
        remote_vti="${UNIFI_VTI_IP}"
        actual_install_state "${name}" || true
        actual_state="${ACTUAL_INSTALL_STATE:-UNKNOWN}"
        case "${actual_state}" in
            INSTALLED|IMPORTED) connection="$(tunnel_connection_state "${name}")" ;;
            PARTIAL) connection="BROKEN" ;;
            *) connection="-" ;;
        esac
        print_table_cell "${display}" "${name_width}"; printf '%s' "${gap}"
        print_table_cell "${interface}" "${interface_width}"; printf '%s' "${gap}"
        case "${connection}" in
            CONNECTED) print_table_cell "${connection}" "${connection_width}" "${C_GREEN}${C_BOLD}" "${C_RESET}" ;;
            DISCONNECTED|BROKEN) print_table_cell "${connection}" "${connection_width}" "${C_RED}${C_BOLD}" "${C_RESET}" ;;
            *) print_table_cell "${connection}" "${connection_width}" ;;
        esac
        printf '%s' "${gap}"
        print_table_cell "${local_vti}" "${vti_width}"; printf '%s' "${gap}"
        print_table_cell "${remote_vti}" "${vti_width}"; printf '\n'
        count=$((count + 1))
    done < <(list_tunnel_names)

    if (( count == 0 )); then
        info "No tunnels are configured."
        pause
        return
    fi

    section "NETWORKS AND TABLE 220 ROUTES"
    print_table_cell "Tunnel" "${name_width}"; printf '%s' "${gap}"
    print_table_cell "Interface" "${interface_width}"; printf '%s' "${gap}"
    print_table_cell "Type" "${type_width}"; printf '%s' "${gap}"
    print_table_cell "Network" "${network_width}"; printf '%s' "${gap}"
    print_table_cell "Table 220 route" "${route_width}"; printf '\n'
    table_divider_segment "${name_width}"; printf '%s' "${gap}"
    table_divider_segment "${interface_width}"; printf '%s' "${gap}"
    table_divider_segment "${type_width}"; printf '%s' "${gap}"
    table_divider_segment "${network_width}"; printf '%s' "${gap}"
    table_divider_segment "${route_width}"; printf '\n'

    while read -r name; do
        [[ -n "${name}" ]] || continue
        load_tunnel "${name}" || continue
        display="${DISPLAY_NAME:-${NAME}}"
        interface="${VTI_INTERFACE}"
        transfer="${VTI_NETWORK}"
        actual_install_state "${name}" || true
        actual_state="${ACTUAL_INSTALL_STATE:-UNKNOWN}"

        if [[ "${actual_state}" == "DEFINED" ]]; then route_state="NOT INSTALLED"; else route_state="$(tunnel_table220_route_state "${transfer}" "${interface}")"; fi
        print_table_cell "${display}" "${name_width}"; printf '%s' "${gap}"
        print_table_cell "${interface}" "${interface_width}"; printf '%s' "${gap}"
        print_table_cell "TRANSFER" "${type_width}"; printf '%s' "${gap}"
        print_table_cell "${transfer}" "${network_width}"; printf '%s' "${gap}"
        print_tunnel_route_state_cell "${route_state}" "${route_width}"; printf '\n'

        while read -r route; do
            [[ -n "${route}" ]] || continue
            if [[ "${actual_state}" == "DEFINED" ]]; then route_state="NOT INSTALLED"; else route_state="$(tunnel_table220_route_state "${route}" "${interface}")"; fi
            print_table_cell "" "${name_width}"; printf '%s' "${gap}"
            print_table_cell "${interface}" "${interface_width}"; printf '%s' "${gap}"
            print_table_cell "REMOTE" "${type_width}"; printf '%s' "${gap}"
            print_table_cell "${route}" "${network_width}"; printf '%s' "${gap}"
            print_tunnel_route_state_cell "${route_state}" "${route_width}"; printf '\n'
        done < <(read_routes "${name}")
    done < <(list_tunnel_names)

    echo
    printf '%bPRESENT%b = route uses the expected interface.  ' "${C_GREEN}" "${C_RESET}"
    printf '%bMISSING / WRONG%b = live routing needs review.\n' "${C_RED}" "${C_RESET}"
    info "A defined but not installed tunnel is labelled NOT INSTALLED instead of MISSING."
    pause
}

show_tunnel_details() {
    local name="$1"
    load_tunnel "${name}" || return 1

    section "Tunnel configuration: ${DISPLAY_NAME}"

    printf '%-28s %s\n' "Display name:" "${DISPLAY_NAME}"
    printf '%-28s %s\n' "Internal name:" "${NAME}"
    printf '%-28s %s\n' "Peer type:" "$(peer_type_label "${PEER_TYPE}")"
    if [[ "${MANAGEMENT}" == "IMPORTED" ]]; then
        printf '%-28s %s\n' "Management:" "IMPORTED / READ-ONLY"
        printf '%-28s %s\n' "Connection:" "$(tunnel_connection_state "${NAME}")"
        printf '%-28s %s\n' "Source connection:" "${SOURCE_CONN_NAME}"
    else
        printf '%-28s %s\n' "Management:" "$([[ "${INSTALLED}" == "1" ]] && echo MANAGED || echo 'DEFINED / MANAGED')"
        printf '%-28s %s\n' "Connection:" "$([[ "${INSTALLED}" == "1" ]] && tunnel_connection_state "${NAME}" || echo '-')"
    fi
    printf '%-28s %s\n' "Local Debian public IP:" "${PUBLIC_IP}"
    printf '%-28s %s\n' "Authentication ID:" "${AUTH_ID}"
    printf '%-28s %s\n' "Peer mode:" "$(peer_mode_label "${PEER_MODE}")"
    if [[ "${PEER_MODE}" != "dynamic" ]]; then
        if [[ "${PEER_TYPE}" == "debian" ]]; then
            printf '%-28s %s\n' "Remote Debian public IP:" "${PEER_ADDRESS}"
        else
            printf '%-28s %s\n' "Peer address:" "${PEER_ADDRESS}"
        fi
    fi
    printf '%-28s %s\n' "VTI interface:" "${VTI_INTERFACE}"
    printf '%-28s %s\n' "VTI key / mark:" "${VTI_KEY}"
    printf '%-28s %s\n' "Tunnel network:" "${VTI_NETWORK}"
    printf '%-28s %s\n' "Local Debian VTI IP:" "${DEBIAN_VTI_IP}"
    if [[ "${PEER_TYPE}" == "debian" ]]; then
        printf '%-28s %s\n' "Remote Debian VTI IP:" "${UNIFI_VTI_IP}"
    else
        printf '%-28s %s\n' "UniFi VTI IP:" "${UNIFI_VTI_IP}"
    fi

    echo
    echo "Remote networks:"
    local r count=0
    while read -r r; do
        [[ -z "${r}" ]] && continue
        printf '  • %s\n' "${r}"
        ((count += 1))
    done < <(read_routes "${name}")
    (( count == 0 )) && echo "  None"
}

rename_tunnel_display_name() {
    banner
    section "RENAME TUNNEL DISPLAY NAME"

    echo "Changes only the human-readable name shown by the S2S Manager."
    echo "The internal name and all strongSwan, VTI, systemd and manager filenames stay unchanged."
    echo "Display names must remain unique."
    echo
    select_tunnel || return

    local name="${SELECTED_TUNNEL}"
    load_tunnel "${name}" || return

    echo
    printf '%-28s %s\n' "Current display name:" "${DISPLAY_NAME}"
    printf '%-28s %s\n' "Internal name:" "${NAME}"
    echo
    echo "Only the display name will change."
    echo "strongSwan connection names, VTI interfaces, systemd services,"
    echo "manager filenames, routes, Authentication ID and PSK remain unchanged."
    echo

    prompt_display_name "${DISPLAY_NAME}" "${NAME}"
    local new_display="${PROMPT_RESULT}"

    if [[ "${new_display}" == "${DISPLAY_NAME}" ]]; then
        info "Display name unchanged."
        pause
        return
    fi

    echo
    printf '%-28s %s\n' "Old display name:" "${DISPLAY_NAME}"
    printf '%-28s %s\n' "New display name:" "${new_display}"
    printf '%-28s %s\n' "Internal name:" "${NAME}"
    echo
    confirm_yes_no "Change tunnel display name?" "N" || return

    if set_tunnel_display_name "${name}" "${new_display}"; then
        ok "Tunnel display name changed."
        info "No active IPsec/VTI/systemd configuration was modified."
    else
        error "Failed to change tunnel display name."
    fi
    pause
}

show_configuration() {
    banner
    section "SHOW TUNNEL CONFIGURATION"

    echo "Shows the complete saved configuration and current connection state of a tunnel."
    echo "This is read-only; no tunnel settings or Debian system files are changed."
    echo
    select_tunnel "all_networks" || return
    if [[ "${SELECTED_TUNNEL}" == "__ALL_NETWORKS__" ]]; then
        show_all_tunnel_networks
        return
    fi
    show_tunnel_details "${SELECTED_TUNNEL}"
    pause
}

print_unifi_config() {
    local name="$1"
    local show_psk="${2:-0}"
    load_tunnel "${name}" || return 1

    local psk_display="••••••••••••••••••••••••••••••••••••••••"
    if (( show_psk == 1 )); then
        psk_display="$(read_psk "${name}" 2>/dev/null || echo '[PSK file not found]')"
    fi

    banner
    printf '%b' "${C_CYAN}${C_BOLD}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    printf '║  %-58s║\n' "UniFi Site-to-Site Configuration"
    printf '║  %-58s║\n' "${NAME}"
    echo "╚══════════════════════════════════════════════════════════════╝"
    printf '%b' "${C_RESET}"

    section "VPN"
    printf '%-32s %s\n' "VPN Type:" "IPsec"
    printf '%-32s %s\n' "Name:" "${NAME}"
    printf '%-32s %s\n' "Pre-Shared Key:" "${psk_display}"

    section "CONNECTION"
    printf '%-32s %s\n' "Local IP:" "Select UniFi WAN interface"
    printf '%-32s %s\n' "Remote IP / Hostname:" "${PUBLIC_IP}"
    printf '%-32s %s\n' "Debian peer mode:" "$(peer_mode_label "${PEER_MODE}")"
    if [[ "${PEER_MODE}" != "dynamic" ]]; then
        printf '%-32s %s\n' "Expected UniFi WAN endpoint:" "${PEER_ADDRESS}"
    fi

    section "NETWORK CONFIGURATION"
    printf '%-32s %s\n' "VPN Method:" "Route Based"
    printf '%-32s %s\n' "Tunnel IP:" "Enabled"
    printf '%-32s %s\n' "IPv4 Address:" "${UNIFI_VTI_IP}"
    printf '%-32s %s\n' "Netmask:" "30"
    printf '%-32s %s\n' "Remote Subnets:" "None"

    section "ADVANCED"
    printf '%-32s %s\n' "Mode:" "Manual"
    printf '%-32s %s\n' "Key Exchange Version:" "IKEv2"

    echo
    printf '%b\n' "${C_BOLD}IKE${C_RESET}"
    printf '%-24s %-18s %-24s %s\n' "Encryption:" "AES-256" "Hash:" "SHA256"
    printf '%-24s %-18s %-24s %s\n' "DH Group:" "14" "Lifetime:" "28800"

    echo
    printf '%b\n' "${C_BOLD}ESP${C_RESET}"
    printf '%-24s %-18s %-24s %s\n' "Encryption:" "AES-256" "Hash:" "SHA256"
    printf '%-24s %-18s %-24s %s\n' "DH Group:" "14" "Lifetime:" "3600"

    echo
    printf '%-32s %s\n' "Perfect Forward Secrecy:" "Enabled"
    printf '%-32s %s\n' "Local Authentication ID:" "${AUTH_ID}"
    printf '%-32s %s\n' "Remote Authentication ID:" "${PUBLIC_IP}"
    printf '%-32s %s\n' "Maximum Transmission Unit:" "Auto"
    printf '%-32s %s\n' "Maximum Segment Size:" "Auto"
    echo
}

show_unifi_configuration() {
    banner
    section "SHOW UNIFI CONFIGURATION"

    echo "Shows the values needed to configure the UniFi side of a UniFi Gateway tunnel."
    echo "This is a reference view only; the manager does not change the UniFi gateway."
    echo
    select_tunnel || return

    local tunnel="${SELECTED_TUNNEL}"
    load_tunnel "${tunnel}" || return

    if [[ "${PEER_TYPE}" == "debian" ]]; then
        warn "This tunnel uses a Debian / strongSwan peer."
        echo "UniFi configuration is not applicable to this tunnel."
        pause
        return
    fi
    if [[ "${MANAGEMENT}" == "IMPORTED" ]]; then
        warn "UniFi configuration display is not generated for imported tunnels."
        echo "The existing external tunnel keeps its original UniFi/IPsec settings."
        echo
        printf '%-28s %s\n' "Source connection:" "${SOURCE_CONN_NAME}"
        printf '%-28s %s\n' "Forced NAT-T:" "$([[ "${SOURCE_FORCED_NATT}" == "1" ]] && echo Yes || echo No)"
        pause
        return
    fi

    local show_psk=0 choice

    while :; do
        print_unifi_config "${tunnel}" "${show_psk}"
        line

        if (( show_psk == 0 )); then
            echo "  [1] Show Pre-Shared Key"
        else
            echo "  [1] Hide Pre-Shared Key"
        fi
        echo "  [B] Back"
        echo "  [E] Exit"
        echo

        read -r -p "Selection: " choice
        case "${choice}" in
            1)
                if (( show_psk == 0 )); then
                    warn "The Pre-Shared Key is sensitive information."
                    confirm_yes_no "Show PSK?" "N" && show_psk=1
                else
                    show_psk=0
                fi
                ;;
            0|""|b|B) return ;;
            e|E) clear_screen; echo "Bye."; exit 0 ;;
            *) error "Invalid selection."; sleep 1 ;;
        esac
    done
}

# ==============================================================================
# Tunnel install/remove menu
# ==============================================================================

install_defined_tunnel() {
    banner
    section "INSTALL TUNNEL ON DEBIAN"

    echo "Installs a saved tunnel definition on this Debian server."
    echo "The manager creates the strongSwan configuration, VTI setup and systemd service"
    echo "and adds the required routing/firewall integration."
    echo "The saved PSK and tunnel definition are reused; the remote peer is not changed."
    echo
    select_tunnel_for_operation "install" || return

    local name="${SELECTED_TUNNEL}"
    load_tunnel "${name}" || return

    actual_install_state "${name}" || return
    case "${ACTUAL_INSTALL_STATE}" in
        DEFINED)
            install_tunnel_system_config "${name}"
            ;;
        PARTIAL)
            section "INCOMPLETE INSTALLATION DETECTED"
            warn "The saved definition and the live Debian installation do not agree."
            printf '%-28s %s
' "Display name:" "${DISPLAY_NAME}"
            printf '%-28s %s
' "Actual state:" "PARTIAL / BROKEN"
            printf '%-28s %s
' "Details:" "${ACTUAL_INSTALL_DETAIL}"
            echo
            echo "  [1] Clean manager-owned system artifacts and install again"
            echo "  [2] Clean manager-owned system artifacts and keep tunnel DEFINED"
            echo "  [B] Back"
            echo
            local choice
            read -r -p "Selection: " choice
            case "${choice}" in
                1)
                    cleanup_partial_install "${name}"
                    install_tunnel_system_config "${name}"
                    ;;
                2)
                    cleanup_partial_install "${name}"
                    pause
                    ;;
                *) return ;;
            esac
            ;;
        INSTALLED)
            warn "Tunnel '${DISPLAY_NAME}' is already fully installed."
            pause
            ;;
        *)
            error "Tunnel installation state could not be determined."
            pause
            ;;
    esac
}

remove_installed_tunnel() {
    banner
    section "REMOVE INSTALLED TUNNEL"

    echo "Removes the manager-installed strongSwan, VTI, systemd and routing configuration"
    echo "from this Debian server, but keeps the tunnel definition and stored PSK."
    echo "The tunnel can therefore be installed again later without recreating it."
    echo
    select_tunnel_for_operation "uninstall" || return

    local name="${SELECTED_TUNNEL}"
    load_tunnel "${name}" || return

    actual_install_state "${name}" || return
    case "${ACTUAL_INSTALL_STATE}" in
        INSTALLED)
            remove_tunnel_system_config "${name}"
            ;;
        PARTIAL)
            section "INCOMPLETE INSTALLATION DETECTED"
            warn "This tunnel is only partially present on Debian."
            printf '%-28s %s
' "Display name:" "${DISPLAY_NAME}"
            printf '%-28s %s
' "Details:" "${ACTUAL_INSTALL_DETAIL}"
            echo
            echo "The tunnel definition and PSK will be kept."
            echo "Only manager-owned system artifacts will be cleaned."
            echo
            confirm_yes_no "Clean the incomplete installation now?" "N" || return
            cleanup_partial_install "${name}"
            pause
            ;;
        *)
            warn "There is no installed Debian system configuration to remove."
            pause
            ;;
    esac
}


# ==============================================================================
# WireGuard full-tunnel VPN
# ==============================================================================

wireguard_server_known() {
    [[ -f "${WG_SERVER_STATE}" ]]
}


wireguard_config_is_manager_owned() {
    local file="${1:-${WG_CONFIG}}"
    [[ -f "${file}" ]] || return 1
    grep -Fq "# Managed by IPsec S2S Manager" "${file}"
}

wireguard_reconcile_management_state() {
    wireguard_server_known || return 0
    load_wireguard_server || return 0

    if [[ "${WG_MANAGEMENT}" == "MANAGED" ]]; then
        if ! wireguard_config_is_manager_owned "${WG_CONFIG}"; then
            # A previously managed state points to a config that is no longer manager-generated.
            # Do not touch the live WireGuard config here; only downgrade manager metadata to IMPORTED.
            local endpoint="${WG_ENDPOINT:-$(detect_public_ipv4)}"
            local dns="${WG_DNS:-${WG_DNS_DEFAULT}}"
            local egress="${WG_EGRESS_IF:-$(detect_default_egress_interface)}"

            save_wireguard_server_state \
                "IMPORTED" "${WG_INTERFACE:-${WG_INTERFACE_DEFAULT}}" "${WG_NETWORK}" "${WG_SERVER_IP}" \
                "${WG_PREFIX}" "${WG_PORT}" "${endpoint}" "${dns}" "${egress}" "${WG_CONFIG}"

            # Existing client metadata may still be valid for display, but managed private-key
            # material must not be trusted after an external/manual restore.
            local id
            while read -r id; do
                [[ -n "${id}" ]] || continue
                local f
                f="$(wireguard_client_state_file "${id}")"
                [[ -f "${f}" ]] || continue
                # Strip manager-owned client private keys after a downgrade to read-only.
                sed -i -E 's/^WG_CLIENT_PRIVATE_KEY=.*/WG_CLIENT_PRIVATE_KEY=/' "${f}" 2>/dev/null || true
            done < <(list_wireguard_client_ids)

            rm -f "${WG_SERVER_KEY}" 2>/dev/null || true
            return 2
        fi
    fi

    return 0
}

wireguard_server_managed() {
    wireguard_server_known || return 1
    load_wireguard_server || return 1
    [[ "${WG_MANAGEMENT}" == "MANAGED" && -f "${WG_SERVER_KEY}" ]] || return 1
    wireguard_config_is_manager_owned "${WG_CONFIG}"
}

wireguard_server_imported() {
    wireguard_server_known || return 1
    load_wireguard_server || return 1
    [[ "${WG_MANAGEMENT}" == "IMPORTED" ]]
}

load_wireguard_server() {
    wireguard_server_known || return 1
    unset WG_MANAGEMENT WG_INTERFACE WG_NETWORK WG_SERVER_IP WG_PREFIX WG_PORT
    unset WG_ENDPOINT WG_DNS WG_EGRESS_IF WG_SOURCE_CONFIG WG_CREATED_AT
    # Manager-owned state only.
    # shellcheck disable=SC1090
    source "${WG_SERVER_STATE}"
    : "${WG_MANAGEMENT:=MANAGED}"
    : "${WG_INTERFACE:=${WG_INTERFACE_DEFAULT}}"
    : "${WG_DNS:=${WG_DNS_DEFAULT}}"
    : "${WG_SOURCE_CONFIG:=}"
}

save_wireguard_server_state() {
    local management="$1"
    local interface="$2"
    local network="$3"
    local server_ip="$4"
    local prefix="$5"
    local port="$6"
    local endpoint="$7"
    local dns="$8"
    local egress="$9"
    local source_config="${10:-}"

    {
        printf 'WG_MANAGEMENT=%q\n' "${management}"
        printf 'WG_INTERFACE=%q\n' "${interface}"
        printf 'WG_NETWORK=%q\n' "${network}"
        printf 'WG_SERVER_IP=%q\n' "${server_ip}"
        printf 'WG_PREFIX=%q\n' "${prefix}"
        printf 'WG_PORT=%q\n' "${port}"
        printf 'WG_ENDPOINT=%q\n' "${endpoint}"
        printf 'WG_DNS=%q\n' "${dns}"
        printf 'WG_EGRESS_IF=%q\n' "${egress}"
        printf 'WG_SOURCE_CONFIG=%q\n' "${source_config}"
        printf 'WG_CREATED_AT=%q\n' "$(date -Is)"
    } > "${WG_SERVER_STATE}"
    chmod 600 "${WG_SERVER_STATE}"
}

wireguard_client_state_file() { printf '%s/%s.client' "${WG_CLIENT_DIR}" "$1"; }
wireguard_client_export_file() { printf '%s/%s.conf' "${WG_CLIENT_EXPORT_DIR}" "$1"; }

wireguard_safe_client_id() {
    local v="$1"
    v="${v// /-}"
    v="$(printf '%s' "${v}" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9._-')"
    [[ -n "${v}" ]] || v="client"
    printf '%s' "${v}"
}

list_wireguard_client_ids() {
    local f
    shopt -s nullglob
    for f in "${WG_CLIENT_DIR}"/*.client; do basename "${f}" .client; done | sort
    shopt -u nullglob
}

load_wireguard_client() {
    local id="$1" f
    f="$(wireguard_client_state_file "${id}")"
    [[ -f "${f}" ]] || return 1
    unset WG_CLIENT_ID WG_CLIENT_NAME WG_CLIENT_IP WG_CLIENT_PRIVATE_KEY
    unset WG_CLIENT_PUBLIC_KEY WG_CLIENT_PRESHARED_KEY WG_CLIENT_CREATED_AT
    # Manager-owned state only.
    # shellcheck disable=SC1090
    source "${f}"
}

detect_default_egress_interface() {
    ip -4 route show default 2>/dev/null |
        awk '{for(i=1;i<=NF;i++) if($i=="dev" && (i+1)<=NF){print $(i+1); exit}}'
}

wireguard_udp_port_in_use() {
    local out
    out="$(ss -H -lun "sport = :$1" 2>/dev/null || true)"
    [[ -n "${out}" ]]
}

wireguard_rule_exists() {
    local status
    ufw_installed || return 1
    status="$(ufw status 2>/dev/null || true)"
    grep -F "S2S Manager WireGuard" <<< "${status}" |
        grep -Eq "(^|[[:space:]])$1/udp([[:space:]]|$)"
}

managed_wireguard_ufw_rule_configured() {
    local port="$1" rules
    ufw_installed || return 1
    rules="$(ufw status 2>/dev/null || true)"
    if grep -F "S2S Manager WireGuard" <<< "${rules}" | grep -Eq "(^|[[:space:]])${port}/udp([[:space:]]|$)"; then
        return 0
    fi
    rules="$(ufw show added 2>/dev/null || true)"
    grep -Fq "ufw allow ${port}/udp comment 'S2S Manager WireGuard'" <<< "${rules}"
}

remove_managed_wireguard_ufw_rules() {
    ufw_installed || return 0
    local nums n
    nums="$(ufw status numbered 2>/dev/null |
        awk '/S2S Manager WireGuard/{n=$1;gsub(/\[|\]/,"",n);print n}' | sort -rn)"
    while read -r n; do
        [[ -n "${n}" ]] && ufw --force delete "${n}" >/dev/null 2>&1 || true
    done <<< "${nums}"

    # Inactive UFW has no numbered live list, but its stored manager rule still
    # needs to be removable during a complete WireGuard reset.
    while ufw show added 2>/dev/null | grep -Fq "ufw allow ${WG_PORT:-${WG_PORT_DEFAULT}}/udp comment 'S2S Manager WireGuard'"; do
        ufw --force delete allow "${WG_PORT:-${WG_PORT_DEFAULT}}/udp" >/dev/null 2>&1 || break
    done
}

ensure_wireguard_firewall_rule() {
    local port="$1" choice ssh_port action proto extra_port desc

    if ! ufw_installed; then
        banner
        section "OPTIONAL UFW FIREWALL SETUP"
        cat <<EOF
UFW is currently not installed.

UFW is NOT required for the WireGuard server.
An external/provider firewall can be used instead.

WireGuard requires its UDP listen port to be reachable from the Internet.

Required WireGuard port:
  UDP ${port}

If UFW is installed and enabled, incoming connections that are not
explicitly allowed may be blocked.

IMPORTANT:
Before enabling UFW, make sure every service you still need is allowed.
EOF
        ssh_port="$(detect_ssh_port)"

        echo
        echo "Detected SSH port: TCP ${ssh_port}"
        echo
        echo "  [1] Install UFW and configure it safely"
        echo "  [2] Continue without UFW"
        echo "  [B] Back"
        echo "  [E] Exit"
        echo
        read -r -p "Selection: " choice
        case "${choice}" in
            1)
                apt-get update || return 1
                DEBIAN_FRONTEND=noninteractive apt-get install -y ufw || return 1
                ufw allow "${ssh_port}/tcp" comment 'S2S Manager SSH safety' >/dev/null || return 1
                ufw allow "${port}/udp" comment 'S2S Manager WireGuard' >/dev/null || return 1

                while :; do
                    banner
                    section "UFW CONFIGURATION SUMMARY"
                    echo "Mandatory rules prepared by the manager:"
                    echo
                    printf "  TCP %-8s SSH / current remote access\n" "${ssh_port}"
                    printf "  UDP %-8s WireGuard VPN\n" "${port}"
                    echo
                    echo "Existing UFW rules are preserved."
                    echo
                    echo "WARNING: Other incoming ports may be blocked after UFW is enabled."
                    echo
                    echo "  [1] Add additional firewall rule"
                    echo "  [2] Review and continue"
                    echo "  [B] Back (UFW remains disabled)"
                    echo "  [E] Exit"
                    echo
                    read -r -p "Selection: " action
                    case "${action}" in
                        1)
                            read -r -p "Protocol [tcp]: " proto
                            proto="${proto:-tcp}"; proto="${proto,,}"
                            [[ "${proto}" == "tcp" || "${proto}" == "udp" ]] || { error "Protocol must be tcp or udp."; pause; continue; }
                            read -r -p "Port: " extra_port
                            [[ "${extra_port}" =~ ^[0-9]+$ ]] && ((extra_port>=1 && extra_port<=65535)) || { error "Invalid port."; pause; continue; }
                            read -r -p "Description [Additional service]: " desc
                            desc="${desc:-Additional service}"
                            ufw allow "${extra_port}/${proto}" comment "S2S Manager ${desc}" >/dev/null || return 1
                            ok "Added ${proto^^} ${extra_port} (${desc})"
                            pause
                            ;;
                        2) break ;;
                        b|B|0) return 0 ;;
                        e|E) clear_screen; echo "Bye."; exit 0 ;;
                    esac
                done

                banner
                section "FINAL UFW SAFETY CHECK"
                ufw status numbered || true
                echo
                echo "Current SSH access detected on TCP port ${ssh_port}."
                local status
                status="$(ufw status 2>/dev/null || true)"
                if ! grep -Eq "(^|[[:space:]])${ssh_port}/tcp[[:space:]]+ALLOW" <<< "${status}"; then
                    error "No matching SSH allow rule found. UFW will NOT be enabled."
                    pause
                    return 0
                fi
                echo
                read -r -p "Enable UFW now? [y/N]: " choice
                if [[ "${choice,,}" == "y" ]]; then
                    ufw default deny incoming >/dev/null
                    ufw default allow outgoing >/dev/null
                    ufw --force enable >/dev/null || return 1
                    ok "UFW enabled."
                else
                    info "UFW installed and rules prepared, but UFW was NOT enabled."
                fi
                ;;
            2)
                info "Allow incoming UDP ${port} in any external/provider firewall."
                ;;
            b|B|0) return 1 ;;
            e|E) clear_screen; echo "Bye."; exit 0 ;;
            *) return 1 ;;
        esac
        return 0
    fi

    if ! ufw_active; then
        info "UFW is installed but inactive."
        echo "The manager will not enable it automatically in this path."
        echo
        echo "  [1] Add managed WireGuard rule and keep UFW disabled"
        echo "  [2] Skip firewall changes"
        echo "  [B] Back"
        echo
        read -r -p "Selection: " choice
        case "${choice}" in
            1) ;;
            2) info "Allow UDP ${port} in any external/provider firewall."; return 0 ;;
            *) return 1 ;;
        esac
    fi

    if ! wireguard_rule_exists "${port}"; then
        remove_managed_wireguard_ufw_rules
        ufw allow "${port}/udp" comment 'S2S Manager WireGuard' >/dev/null || return 1
    fi
    ok "Managed WireGuard firewall rule is present (UDP ${port})."
}

install_wireguard_packages() {
    local -a need=()
    package_installed wireguard-tools || need+=(wireguard-tools)
    package_installed qrencode || need+=(qrencode)
    package_installed iptables || need+=(iptables)
    (( ${#need[@]} == 0 )) && { ok "WireGuard packages already installed."; return 0; }
    info "Installing: ${need[*]}"
    apt-get update &&
        DEBIAN_FRONTEND=noninteractive apt-get install -y "${need[@]}"
}

write_wireguard_sysctl() {
    cat > "${WG_SYSCTL_FILE}" <<'EOF'
# Managed by IPsec S2S Manager - WireGuard full-tunnel VPN
net.ipv4.ip_forward = 1
EOF
    chmod 644 "${WG_SYSCTL_FILE}"
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
}

wireguard_next_client_ip() {
    load_wireguard_server || return 1
    [[ "${WG_PREFIX}" == "24" ]] || return 1
    local base n h candidate id used
    base="${WG_NETWORK%%/*}"
    n="$(ipv4_to_int "${base}")"
    for ((h=2;h<=254;h++)); do
        candidate="$(int_to_ipv4 "$((n+h))")"
        used=0
        while read -r id; do
            [[ -n "${id}" ]] || continue
            load_wireguard_client "${id}" || continue
            [[ "${WG_CLIENT_IP}" == "${candidate}" ]] && { used=1; break; }
        done < <(list_wireguard_client_ids)
        ((used==0)) && { printf '%s' "${candidate}"; return 0; }
    done
    return 1
}


wireguard_table220_active() {
    local rules
    rules="$(ip rule show 2>/dev/null || true)"
    grep -Eq '(^|[[:space:]])220:.*lookup[[:space:]]+220([[:space:]]|$)' <<< "${rules}"
}

wireguard_table220_route_ok() {
    load_wireguard_server || return 1
    local route
    route="$(ip route show table 220 "${WG_NETWORK}" 2>/dev/null || true)"
    grep -Eq "^${WG_NETWORK//./\\.} dev ${WG_INTERFACE}([[:space:]]|$)" <<< "${route}"
}

wireguard_ensure_table220_route() {
    load_wireguard_server || return 1
    wireguard_table220_active || return 0
    ip route replace "${WG_NETWORK}" dev "${WG_INTERFACE}" table 220 || return 1
}

wireguard_remove_table220_route() {
    load_wireguard_server || return 1
    wireguard_table220_active || return 0
    ip route del "${WG_NETWORK}" dev "${WG_INTERFACE}" table 220 2>/dev/null || true
}

wireguard_cleanup_legacy_rules() {
    load_wireguard_server || return 1
    local net="${WG_NETWORK}"
    local public_ip
    public_ip="$(detect_public_ipv4)"

    # Remove common legacy FORWARD rules that match this WG network exactly.
    while iptables -C FORWARD -s "${net}" -j ACCEPT >/dev/null 2>&1; do
        iptables -D FORWARD -s "${net}" -j ACCEPT >/dev/null 2>&1 || break
    done

    while iptables -C FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1; do
        # Do not remove broad global rules; only one copy is enough to coexist safely.
        break
    done

    # Remove legacy SNAT rules for the WG network to the server public IP.
    if [[ -n "${public_ip}" ]]; then
        while iptables -t nat -C POSTROUTING -s "${net}" ! -d "${net}" -j SNAT --to-source "${public_ip}" >/dev/null 2>&1; do
            iptables -t nat -D POSTROUTING -s "${net}" ! -d "${net}" -j SNAT --to-source "${public_ip}" >/dev/null 2>&1 || break
        done
    fi

    # Remove duplicate manager-style MASQUERADE/FORWARD rules before wg-quick restarts.
    while iptables -C FORWARD -i "${WG_INTERFACE}" -j ACCEPT >/dev/null 2>&1; do
        iptables -D FORWARD -i "${WG_INTERFACE}" -j ACCEPT >/dev/null 2>&1 || break
    done
    while iptables -C FORWARD -o "${WG_INTERFACE}" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1; do
        iptables -D FORWARD -o "${WG_INTERFACE}" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1 || break
    done
    while iptables -t nat -C POSTROUTING -s "${net}" -o "${WG_EGRESS_IF}" -j MASQUERADE >/dev/null 2>&1; do
        iptables -t nat -D POSTROUTING -s "${net}" -o "${WG_EGRESS_IF}" -j MASQUERADE >/dev/null 2>&1 || break
    done
}

render_wireguard_server_config() {
    load_wireguard_server || return 1
    [[ "${WG_MANAGEMENT}" == "MANAGED" ]] || return 1
    local private id tmp
    private="$(cat "${WG_SERVER_KEY}" 2>/dev/null || true)"
    [[ -n "${private}" ]] || return 1
    mkdir -p "${WG_CONFIG_DIR}"; chmod 700 "${WG_CONFIG_DIR}"
    tmp="$(mktemp)"
    {
        echo "# Managed by IPsec S2S Manager"
        echo "[Interface]"
        printf 'Address = %s/%s\n' "${WG_SERVER_IP}" "${WG_PREFIX}"
        printf 'ListenPort = %s\n' "${WG_PORT}"
        printf 'PrivateKey = %s\n' "${private}"
        printf 'PostUp = iptables -A FORWARD -i %%i -j ACCEPT; iptables -A FORWARD -o %%i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE; if ip rule show | grep -Eq "(^|[[:space:]])220:.*lookup[[:space:]]+220([[:space:]]|$)"; then ip route replace %s dev %%i table 220; fi\n' "${WG_NETWORK}" "${WG_EGRESS_IF}" "${WG_NETWORK}"
        printf 'PostDown = iptables -D FORWARD -i %%i -j ACCEPT 2>/dev/null || true; iptables -D FORWARD -o %%i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true; iptables -t nat -D POSTROUTING -s %s -o %s -j MASQUERADE 2>/dev/null || true; if ip rule show | grep -Eq "(^|[[:space:]])220:.*lookup[[:space:]]+220([[:space:]]|$)"; then ip route del %s dev %%i table 220 2>/dev/null || true; fi\n' "${WG_NETWORK}" "${WG_EGRESS_IF}" "${WG_NETWORK}"
        while read -r id; do
            [[ -n "${id}" ]] || continue
            load_wireguard_client "${id}" || continue
            echo
            printf '# Client: %s\n' "${WG_CLIENT_NAME}"
            echo "[Peer]"
            printf 'PublicKey = %s\n' "${WG_CLIENT_PUBLIC_KEY}"
            if [[ -n "${WG_CLIENT_PRESHARED_KEY}" ]]; then
                printf 'PresharedKey = %s\n' "${WG_CLIENT_PRESHARED_KEY}"
            fi
            printf 'AllowedIPs = %s/32\n' "${WG_CLIENT_IP}"
        done < <(list_wireguard_client_ids)
    } > "${tmp}"
    install -m 600 "${tmp}" "${WG_CONFIG}"
    rm -f "${tmp}"
}

wireguard_apply() {
    load_wireguard_server || return 1
    [[ "${WG_MANAGEMENT}" == "MANAGED" ]] || return 1

    wireguard_cleanup_legacy_rules || true
    render_wireguard_server_config || return 1

    systemctl enable "wg-quick@${WG_INTERFACE}" >/dev/null 2>&1 || return 1
    if ! systemctl restart "wg-quick@${WG_INTERFACE}" >/tmp/s2s-manager-wireguard-restart.log 2>&1; then
        cat /tmp/s2s-manager-wireguard-restart.log 2>/dev/null || true
        return 1
    fi
    wireguard_ensure_table220_route || return 1
    systemctl is-active --quiet "wg-quick@${WG_INTERFACE}"
}

wireguard_create_manager_backup() {
    local reason="${1:-manual}" dir
    dir="$(mktemp -d "${WG_BACKUP_DIR}/${WG_INTERFACE}-$(date +%Y%m%d-%H%M%S)-${reason}.XXXXXX")" || return 1
    mkdir -p "${dir}/clients" "${dir}/exports" || return 1
    chmod 700 "${dir}" "${dir}/clients" "${dir}/exports"
    [[ ! -f "${WG_SERVER_STATE}" ]] || cp -a -- "${WG_SERVER_STATE}" "${dir}/server.conf" || return 1
    [[ ! -f "${WG_SERVER_KEY}" ]] || cp -a -- "${WG_SERVER_KEY}" "${dir}/server.key" || return 1
    [[ ! -f "${WG_CONFIG}" ]] || cp -a -- "${WG_CONFIG}" "${dir}/$(basename "${WG_CONFIG}")" || return 1
    [[ ! -f "${WG_SYSCTL_FILE}" ]] || cp -a -- "${WG_SYSCTL_FILE}" "${dir}/$(basename "${WG_SYSCTL_FILE}")" || return 1
    if [[ -d "${WG_CLIENT_DIR}" ]]; then cp -a -- "${WG_CLIENT_DIR}/." "${dir}/clients/" || return 1; fi
    if [[ -d "${WG_CLIENT_EXPORT_DIR}" ]]; then cp -a -- "${WG_CLIENT_EXPORT_DIR}/." "${dir}/exports/" || return 1; fi
    systemctl status "wg-quick@${WG_INTERFACE}" --no-pager -l > "${dir}/service-status.txt" 2>&1 || true
    wg show "${WG_INTERFACE}" > "${dir}/wg-show.txt" 2>&1 || true
    ip route show table 220 > "${dir}/table-220.txt" 2>&1 || true
    WG_LAST_MANAGER_BACKUP="${dir}"
}

wireguard_restore_manager_backup() {
    local dir="$1" config_name
    [[ -d "${dir}" && -f "${dir}/server.conf" && -f "${dir}/server.key" ]] || return 1
    config_name="$(basename "${WG_CONFIG}")"
    install -m 600 "${dir}/server.conf" "${WG_SERVER_STATE}" || return 1
    install -m 600 "${dir}/server.key" "${WG_SERVER_KEY}" || return 1
    [[ -f "${dir}/${config_name}" ]] && install -m 600 "${dir}/${config_name}" "${WG_CONFIG}"
    if [[ -f "${dir}/$(basename "${WG_SYSCTL_FILE}")" ]]; then
        install -m 644 "${dir}/$(basename "${WG_SYSCTL_FILE}")" "${WG_SYSCTL_FILE}"
    fi
    rm -f -- "${WG_CLIENT_DIR}"/*.client "${WG_CLIENT_EXPORT_DIR}"/*.conf 2>/dev/null || true
    cp -a -- "${dir}/clients/." "${WG_CLIENT_DIR}/" || return 1
    cp -a -- "${dir}/exports/." "${WG_CLIENT_EXPORT_DIR}/" || return 1
}

wireguard_set_client_ip() {
    local id="$1" new_ip="$2" file
    valid_ipv4 "${new_ip}" || return 1
    file="$(wireguard_client_state_file "${id}")"
    [[ -f "${file}" ]] || return 1
    sed -i -E "s|^WG_CLIENT_IP=.*$|WG_CLIENT_IP=${new_ip}|" "${file}" || return 1
    load_wireguard_client "${id}" || return 1
    [[ "${WG_CLIENT_IP}" == "${new_ip}" ]]
}

wireguard_mapped_client_ip() {
    local old_network="$1" new_network="$2" old_ip="$3"
    local old_base new_base old_base_int new_base_int host
    old_base="${old_network%%/*}"; new_base="${new_network%%/*}"
    old_base_int="$(ipv4_to_int "${old_base}")" || return 1
    new_base_int="$(ipv4_to_int "${new_base}")" || return 1
    host=$(( $(ipv4_to_int "${old_ip}") - old_base_int ))
    (( host >= 2 && host <= 254 )) || return 1
    int_to_ipv4 "$((new_base_int + host))"
}

wireguard_change_vpn_network() {
    wireguard_server_managed || { warn "Only a manager-owned WireGuard server can be changed."; pause; return; }
    load_wireguard_server || return
    banner
    section "CHANGE WIREGUARD VPN NETWORK"
    cat <<EOF
Changes the private IPv4 /24 network used by the WireGuard server and clients.

The server keeps its WireGuard key. Every client keeps its private/public key
and preshared key. Client host numbers are preserved: for example, client .5
in ${WG_NETWORK} becomes client .5 in the new network.

Existing client devices stop connecting until their local [Interface] Address
is changed to the displayed new address or the regenerated configuration/QR
code is imported. Endpoint, port, DNS and full-tunnel AllowedIPs stay unchanged.
EOF
    echo
    local requested normalized prefix new_base new_server new_base_int
    local id new_ip client_count=0 backup old_network="${WG_NETWORK}" migration_ok=1
    read -r -p "New WireGuard VPN network (IPv4 /24): " requested
    case "${requested,,}" in b|back) return ;; e|exit) clear_screen; echo "Bye."; exit 0 ;; esac
    valid_cidr "${requested}" || { error "Enter a valid IPv4 CIDR such as 10.60.0.0/24."; pause; return; }
    normalized="$(cidr_normalized "${requested}")" || { error "Could not normalize the network."; pause; return; }
    prefix="${normalized#*/}"
    [[ "${prefix}" == "24" ]] || { error "WireGuard network migration currently supports IPv4 /24 networks."; pause; return; }
    [[ "${requested}" == "${normalized}" ]] || { error "Enter the network base address. Use ${normalized}."; pause; return; }
    [[ "${normalized}" != "${WG_NETWORK}" ]] || { info "The requested network is already configured."; pause; return; }
    if check_network_conflict "${normalized}" "" "${WG_INTERFACE}"; then
        show_network_conflict "${normalized}"; pause; return
    fi

    new_base="${normalized%%/*}"
    new_base_int="$(ipv4_to_int "${new_base}")"
    new_server="$(int_to_ipv4 "$((new_base_int + 1))")"
    while read -r id; do [[ -n "${id}" ]] && ((client_count+=1)); done < <(list_wireguard_client_ids)

    echo
    section "WIREGUARD NETWORK CHANGE PREVIEW"
    printf '%-28s %s\n' "Old VPN network:" "${WG_NETWORK}"
    printf '%-28s %s\n' "New VPN network:" "${normalized}"
    printf '%-28s %s/%s\n' "New server VPN IP:" "${new_server}" "${prefix}"
    printf '%-28s %s\n' "Clients to update:" "${client_count}"
    echo
    while read -r id; do
        [[ -n "${id}" ]] || continue
        if ! load_wireguard_client "${id}"; then
            error "Client state '${id}' cannot be loaded; migration stopped."
            pause; return
        fi
        if ! new_ip="$(wireguard_mapped_client_ip "${WG_NETWORK}" "${normalized}" "${WG_CLIENT_IP}")"; then
            error "Client '${WG_CLIENT_NAME}' has unexpected address ${WG_CLIENT_IP}; migration stopped."
            pause; return
        fi
        printf '  %-24s %s -> %s\n' "${WG_CLIENT_NAME}" "${WG_CLIENT_IP}" "${new_ip}"
    done < <(list_wireguard_client_ids)
    echo
    warn "WireGuard clients will be interrupted until their client Address is updated."
    confirm_yes_no "Change the WireGuard VPN network now?" "N" || return

    wireguard_create_manager_backup "network-change" || { error "Could not create the safety backup."; pause; return; }
    backup="${WG_LAST_MANAGER_BACKUP}"
    systemctl stop "wg-quick@${WG_INTERFACE}" >/dev/null 2>&1 || true
    wireguard_remove_table220_route || true
    wireguard_cleanup_legacy_rules || true
    save_wireguard_server_state "MANAGED" "${WG_INTERFACE}" "${normalized}" "${new_server}" "${prefix}" \
        "${WG_PORT}" "${WG_ENDPOINT}" "${WG_DNS}" "${WG_EGRESS_IF}" ""
    while read -r id; do
        [[ -n "${id}" ]] || continue
        load_wireguard_client "${id}" || { migration_ok=0; break; }
        new_ip="$(wireguard_mapped_client_ip "${old_network}" "${normalized}" "${WG_CLIENT_IP}")" || { migration_ok=0; break; }
        if ! wireguard_set_client_ip "${id}" "${new_ip}" || ! wireguard_render_client_export "${id}"; then
            migration_ok=0
            break
        fi
    done < <(list_wireguard_client_ids)

    if (( migration_ok == 1 )) && wireguard_apply; then
        ok "WireGuard VPN network changed successfully."
        printf '%-28s %s\n' "New VPN network:" "${normalized}"
        printf '%-28s %s/%s\n' "New server VPN IP:" "${new_server}" "${prefix}"
        printf '%-28s %s\n' "Safety backup:" "${backup}"
        (( client_count > 0 )) && warn "Update/import each client configuration before testing that client."
    else
        error "The new WireGuard state could not be applied completely. Restoring ${old_network}..."
        systemctl stop "wg-quick@${WG_INTERFACE}" >/dev/null 2>&1 || true
        wireguard_cleanup_legacy_rules || true
        wireguard_restore_manager_backup "${backup}" && wireguard_apply \
            && ok "Rollback successful; the previous WireGuard network is active." \
            || error "Automatic rollback failed. Backup: ${backup}"
    fi
    pause
}

wireguard_remove_managed_server() {
    wireguard_server_managed || { warn "Only a manager-owned WireGuard server can be removed here."; pause; return; }
    load_wireguard_server || return
    banner
    section "REMOVE / RESET WIREGUARD SERVER"
    cat <<EOF
This completely removes the manager-owned WireGuard server configuration.

It stops and disables wg-quick@${WG_INTERFACE}, removes its live routing/NAT
rules, table 220 route, server key, client keys/state and generated exports.
WireGuard packages remain installed. S2S/IPsec tunnels are not changed.

A safety backup is created first so the configuration can be recovered
manually. Existing client devices will no longer connect after this reset.
EOF
    echo
    wireguard_server_summary
    echo
    warn "This removes private key material from the active manager state."
    local typed backup remove_ufw="n"
    read -r -p "Type RESET WIREGUARD to continue: " typed
    [[ "${typed}" == "RESET WIREGUARD" ]] || { info "Reset cancelled."; pause; return; }
    if managed_wireguard_ufw_rule_configured "${WG_PORT}"; then
        confirm_yes_no "Also remove the managed UFW WireGuard rule for UDP ${WG_PORT}?" "N" && remove_ufw="y"
    fi
    wireguard_create_manager_backup "reset" || { error "Could not create the safety backup. Reset cancelled."; pause; return; }
    backup="${WG_LAST_MANAGER_BACKUP}"
    systemctl stop "wg-quick@${WG_INTERFACE}" >/dev/null 2>&1 || true
    systemctl disable "wg-quick@${WG_INTERFACE}" >/dev/null 2>&1 || true
    wireguard_remove_table220_route || true
    wireguard_cleanup_legacy_rules || true
    [[ "${remove_ufw}" == "y" ]] && remove_managed_wireguard_ufw_rules
    wireguard_config_is_manager_owned "${WG_CONFIG}" && rm -f -- "${WG_CONFIG}"
    rm -f -- "${WG_SERVER_STATE}" "${WG_SERVER_KEY}" "${WG_SYSCTL_FILE}"
    rm -f -- "${WG_CLIENT_DIR}"/*.client "${WG_CLIENT_EXPORT_DIR}"/*.conf 2>/dev/null || true
    systemctl daemon-reload >/dev/null 2>&1 || true
    ok "Manager-owned WireGuard server removed."
    printf '%-28s %s\n' "Recovery backup:" "${backup}"
    info "WireGuard packages remain installed; server setup can now start from the beginning."
    pause
}

# Update only WireGuard peer state without restarting wg0. This preserves
# existing handshakes, traffic counters and active client sessions.
wireguard_sync_peers_live() {
    load_wireguard_server || return 1
    [[ "${WG_MANAGEMENT}" == "MANAGED" ]] || return 1

    render_wireguard_server_config || return 1

    if ! systemctl is-active --quiet "wg-quick@${WG_INTERFACE}" 2>/dev/null; then
        wireguard_apply
        return $?
    fi

    local stripped
    stripped="$(mktemp)" || return 1
    if ! wg-quick strip "${WG_INTERFACE}" > "${stripped}" 2>/tmp/s2s-manager-wireguard-strip.log; then
        rm -f "${stripped}"
        return 1
    fi

    if ! wg syncconf "${WG_INTERFACE}" "${stripped}" >/tmp/s2s-manager-wireguard-sync.log 2>&1; then
        rm -f "${stripped}"
        cat /tmp/s2s-manager-wireguard-sync.log 2>/dev/null || true
        return 1
    fi
    rm -f "${stripped}"

    wireguard_ensure_table220_route || return 1
    return 0
}

wireguard_server_summary() {
    load_wireguard_server || return 1
    local state="inactive" pub="" private=""
    systemctl is-active --quiet "wg-quick@${WG_INTERFACE}" 2>/dev/null && state="active"

    if command_available wg; then
        if [[ "${WG_MANAGEMENT}" == "IMPORTED" ]]; then
            # Read-only imports deliberately do not copy/store the server private key.
            # Read the public key from the live interface instead.
            pub="$(wg show "${WG_INTERFACE}" public-key 2>/dev/null || true)"
        elif [[ -f "${WG_SERVER_KEY}" ]]; then
            private="$(cat "${WG_SERVER_KEY}" 2>/dev/null || true)"
            [[ -n "${private}" ]] && pub="$(printf '%s' "${private}" | wg pubkey 2>/dev/null || true)"
        fi
    fi
    printf '%-28s %s\n' "Management:" "${WG_MANAGEMENT}"
    printf '%-28s %s\n' "Service:" "${state}"
    printf '%-28s %s\n' "Interface:" "${WG_INTERFACE}"
    printf '%-28s %s\n' "VPN network:" "${WG_NETWORK}"
    printf '%-28s %s/%s\n' "Server VPN IP:" "${WG_SERVER_IP}" "${WG_PREFIX}"
    printf '%-28s UDP %s\n' "Listen port:" "${WG_PORT}"
    printf '%-28s %s\n' "Public endpoint:" "${WG_ENDPOINT}"
    printf '%-28s %s\n' "Client DNS:" "${WG_DNS}"
    printf '%-28s %s\n' "Internet egress:" "${WG_EGRESS_IF}"
    [[ -n "${pub}" ]] && printf '%-28s %s\n' "Server public key:" "${pub}"
}

wireguard_render_client_export() {
    local id="$1" server_private server_public out
    load_wireguard_server || return 1
    load_wireguard_client "${id}" || return 1
    server_private="$(cat "${WG_SERVER_KEY}")"
    server_public="$(printf '%s' "${server_private}" | wg pubkey)" || return 1
    out="$(wireguard_client_export_file "${id}")"
    {
        echo "# WireGuard client generated by IPsec S2S Manager"
        echo "[Interface]"
        printf 'PrivateKey = %s\n' "${WG_CLIENT_PRIVATE_KEY}"
        printf 'Address = %s/32\n' "${WG_CLIENT_IP}"
        printf 'DNS = %s\n' "${WG_DNS}"
        echo
        echo "[Peer]"
        printf 'PublicKey = %s\n' "${server_public}"
        if [[ -n "${WG_CLIENT_PRESHARED_KEY}" ]]; then
            printf 'PresharedKey = %s\n' "${WG_CLIENT_PRESHARED_KEY}"
        fi
        printf 'Endpoint = %s:%s\n' "${WG_ENDPOINT}" "${WG_PORT}"
        echo 'AllowedIPs = 0.0.0.0/0'
        echo 'PersistentKeepalive = 25'
    } > "${out}"
    chmod 600 "${out}"
}


wireguard_existing_configs() {
    local f
    shopt -s nullglob
    for f in /etc/wireguard/*.conf; do
        [[ -f "${f}" ]] && printf '%s\n' "${f}"
    done
    shopt -u nullglob
}

wireguard_parse_existing_config() {
    local file="$1"
    [[ -f "${file}" ]] || return 1

    DISC_WG_FILE="${file}"
    DISC_WG_INTERFACE="$(basename "${file}" .conf)"
    DISC_WG_ADDRESS=""
    DISC_WG_PORT=""
    DISC_WG_PRIVATE_KEY=""
    DISC_WG_POSTUP=""
    DISC_WG_POSTDOWN=""
    DISC_WG_COMPATIBLE=1
    DISC_WG_REASON=""
    DISC_WG_PEER_PUBLIC_KEYS=()
    DISC_WG_PEER_PSKS=()
    DISC_WG_PEER_ALLOWED=()
    DISC_WG_PEER_NAMES=()

    local section="" line key value peer_index=-1 comment_name="" trimmed
    while IFS= read -r line || [[ -n "${line}" ]]; do
        trimmed="${line#"${line%%[![:space:]]*}"}"
        trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
        [[ -z "${trimmed}" ]] && continue

        if [[ "${trimmed}" == \#* ]]; then
            if [[ "${trimmed}" =~ ^#[[:space:]]*Client:[[:space:]]*(.+)$ ]]; then
                comment_name="${BASH_REMATCH[1]}"
            fi
            continue
        fi

        case "${trimmed}" in
            "[Interface]")
                section="Interface"
                ;;
            "[Peer]")
                section="Peer"
                ((peer_index += 1))
                DISC_WG_PEER_PUBLIC_KEYS[peer_index]=""
                DISC_WG_PEER_PSKS[peer_index]=""
                DISC_WG_PEER_ALLOWED[peer_index]=""
                if [[ -n "${comment_name}" ]]; then
                    DISC_WG_PEER_NAMES[peer_index]="${comment_name}"
                else
                    DISC_WG_PEER_NAMES[peer_index]="Imported peer $((peer_index + 1))"
                fi
                comment_name=""
                ;;
            *=*)
                key="${trimmed%%=*}"
                value="${trimmed#*=}"
                key="${key%"${key##*[![:space:]]}"}"
                value="${value#"${value%%[![:space:]]*}"}"
                value="${value%"${value##*[![:space:]]}"}"

                if [[ "${section}" == "Interface" ]]; then
                    case "${key}" in
                        Address)
                            if [[ -z "${DISC_WG_ADDRESS}" ]]; then
                                DISC_WG_ADDRESS="${value%%,*}"
                                DISC_WG_ADDRESS="${DISC_WG_ADDRESS//[[:space:]]/}"
                            fi
                            ;;
                        ListenPort) DISC_WG_PORT="${value}" ;;
                        PrivateKey) DISC_WG_PRIVATE_KEY="${value}" ;;
                        PostUp) DISC_WG_POSTUP+="${value}"$'\n' ;;
                        PostDown) DISC_WG_POSTDOWN+="${value}"$'\n' ;;
                        DNS|MTU|Table|PreUp|PreDown|SaveConfig)
                            ;;
                        *)
                            DISC_WG_COMPATIBLE=0
                            DISC_WG_REASON="unsupported Interface directive: ${key}"
                            ;;
                    esac
                elif [[ "${section}" == "Peer" && ${peer_index} -ge 0 ]]; then
                    case "${key}" in
                        PublicKey) DISC_WG_PEER_PUBLIC_KEYS[peer_index]="${value}" ;;
                        PresharedKey) DISC_WG_PEER_PSKS[peer_index]="${value}" ;;
                        AllowedIPs) DISC_WG_PEER_ALLOWED[peer_index]="${value}" ;;
                        Endpoint|PersistentKeepalive)
                            # Valid server config directives, but not required for migration.
                            ;;
                        *)
                            DISC_WG_COMPATIBLE=0
                            DISC_WG_REASON="unsupported Peer directive: ${key}"
                            ;;
                    esac
                fi
                ;;
            *)
                DISC_WG_COMPATIBLE=0
                DISC_WG_REASON="unrecognized line in configuration"
                ;;
        esac
    done < "${file}"

    if ! valid_cidr "${DISC_WG_ADDRESS}"; then
        DISC_WG_COMPATIBLE=0
        DISC_WG_REASON="missing or unsupported IPv4 Address"
        return 0
    fi

    local addr_ip="${DISC_WG_ADDRESS%%/*}"
    local prefix="${DISC_WG_ADDRESS##*/}"
    if [[ "${prefix}" != "24" ]]; then
        DISC_WG_COMPATIBLE=0
        DISC_WG_REASON="manager migration currently requires a /24 WireGuard network"
    fi

    DISC_WG_SERVER_IP="${addr_ip}"
    DISC_WG_PREFIX="${prefix}"
    DISC_WG_NETWORK="$(cidr_normalized "${DISC_WG_ADDRESS}")"

    if [[ -z "${DISC_WG_PORT}" ]] && command_available wg &&
       ip link show "${DISC_WG_INTERFACE}" >/dev/null 2>&1; then
        DISC_WG_PORT="$(wg show "${DISC_WG_INTERFACE}" listen-port 2>/dev/null || true)"
    fi
    [[ "${DISC_WG_PORT}" =~ ^[0-9]+$ ]] || {
        DISC_WG_COMPATIBLE=0
        DISC_WG_REASON="ListenPort could not be determined"
    }

    [[ -n "${DISC_WG_PRIVATE_KEY}" ]] || {
        DISC_WG_COMPATIBLE=0
        DISC_WG_REASON="PrivateKey is not present in the configuration file"
    }

    local i allowed
    for i in "${!DISC_WG_PEER_PUBLIC_KEYS[@]}"; do
        [[ -n "${DISC_WG_PEER_PUBLIC_KEYS[$i]}" ]] || {
            DISC_WG_COMPATIBLE=0
            DISC_WG_REASON="peer $((i+1)) has no PublicKey"
            continue
        }
        allowed="${DISC_WG_PEER_ALLOWED[$i]}"
        if [[ ! "${allowed}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/32$ ]]; then
            DISC_WG_COMPATIBLE=0
            DISC_WG_REASON="peer $((i+1)) AllowedIPs is not exactly one IPv4 /32"
        fi
    done

    return 0
}

wireguard_show_discovered_config() {
    wireguard_parse_existing_config "$1" || return 1

    local active="inactive"
    ip link show "${DISC_WG_INTERFACE}" >/dev/null 2>&1 && active="active"

    printf '%-28s %s\n' "Config file:" "${DISC_WG_FILE}"
    printf '%-28s %s\n' "Interface:" "${DISC_WG_INTERFACE}"
    printf '%-28s %s\n' "Interface state:" "${active}"
    printf '%-28s %s\n' "VPN address:" "${DISC_WG_ADDRESS:-unknown}"
    printf '%-28s UDP %s\n' "Listen port:" "${DISC_WG_PORT:-unknown}"
    printf '%-28s %s\n' "Peers:" "${#DISC_WG_PEER_PUBLIC_KEYS[@]}"
    if (( DISC_WG_COMPATIBLE == 1 )); then
        printf '%-28s %s\n' "Manager migration:" "SUPPORTED"
    else
        printf '%-28s %s\n' "Manager migration:" "NOT SUPPORTED"
        printf '%-28s %s\n' "Reason:" "${DISC_WG_REASON}"
    fi

    echo
    if [[ -n "${DISC_WG_POSTUP}" || -n "${DISC_WG_POSTDOWN}" ]]; then
        echo "Existing PostUp/PostDown commands were detected."
        echo "Read-only import preserves them because it changes nothing."
        echo "A manager migration replaces them with the manager's full-tunnel NAT/forwarding rules."
    fi
}

wireguard_select_existing_config() {
    local -a configs=()
    local f i choice

    while read -r f; do
        [[ -n "${f}" ]] && configs+=("${f}")
    done < <(wireguard_existing_configs)

    if (( ${#configs[@]} == 0 )); then
        warn "No existing /etc/wireguard/*.conf configuration was found."
        pause
        return 1
    fi

    echo
    for i in "${!configs[@]}"; do
        wireguard_parse_existing_config "${configs[$i]}" || continue
        printf '  [%d] %-14s %s  UDP %s\n' \
            "$((i+1))" "${DISC_WG_INTERFACE}" "${DISC_WG_ADDRESS:-unknown}" "${DISC_WG_PORT:-unknown}"
    done
    echo
    echo "B = Back    E = Exit"
    echo
    read -r -p "Selection: " choice

    case "${choice}" in
        b|B|0|"") return 1 ;;
        e|E) clear_screen; echo "Bye."; exit 0 ;;
    esac
    [[ "${choice}" =~ ^[0-9]+$ ]] || return 1
    (( choice >= 1 && choice <= ${#configs[@]} )) || return 1
    SELECTED_WG_EXISTING="${configs[$((choice-1))]}"
}

wireguard_clear_imported_clients() {
    rm -f "${WG_CLIENT_DIR}"/*.client 2>/dev/null || true
    rm -f "${WG_CLIENT_EXPORT_DIR}"/*.conf 2>/dev/null || true
}

wireguard_import_existing_peers_readonly() {
    local i id name ip psk
    wireguard_clear_imported_clients

    for i in "${!DISC_WG_PEER_PUBLIC_KEYS[@]}"; do
        name="${DISC_WG_PEER_NAMES[$i]}"
        id="imported-$((i+1))"
        ip="${DISC_WG_PEER_ALLOWED[$i]%/32}"
        psk="${DISC_WG_PEER_PSKS[$i]}"

        {
            printf 'WG_CLIENT_ID=%q\n' "${id}"
            printf 'WG_CLIENT_NAME=%q\n' "${name}"
            printf 'WG_CLIENT_IP=%q\n' "${ip}"
            printf 'WG_CLIENT_PRIVATE_KEY=%q\n' ""
            printf 'WG_CLIENT_PUBLIC_KEY=%q\n' "${DISC_WG_PEER_PUBLIC_KEYS[$i]}"
            printf 'WG_CLIENT_PRESHARED_KEY=%q\n' "${psk}"
            printf 'WG_CLIENT_CREATED_AT=%q\n' "imported"
        } > "$(wireguard_client_state_file "${id}")"
        chmod 600 "$(wireguard_client_state_file "${id}")"
    done
}

wireguard_import_existing_readonly() {
    local file="$1"
    wireguard_parse_existing_config "${file}" || return 1

    local endpoint egress
    endpoint="$(detect_public_ipv4)"
    egress="$(detect_default_egress_interface)"

    save_wireguard_server_state \
        "IMPORTED" "${DISC_WG_INTERFACE}" "${DISC_WG_NETWORK}" "${DISC_WG_SERVER_IP}" \
        "${DISC_WG_PREFIX}" "${DISC_WG_PORT}" "${endpoint}" "${WG_DNS_DEFAULT}" \
        "${egress}" "${file}"

    wireguard_import_existing_peers_readonly

    echo
    ok "Existing WireGuard server imported as READ-ONLY."
    info "No WireGuard file, interface, firewall rule or running peer was changed."
    info "Use 'Migrate / take over imported WireGuard server' when you want manager ownership."
}

wireguard_backup_existing_config() {
    local file="$1" interface="$2" dir
    dir="${WG_BACKUP_DIR}/${interface}-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "${dir}"
    chmod 700 "${dir}"

    cp -a -- "${file}" "${dir}/$(basename "${file}")" || return 1
    systemctl status "wg-quick@${interface}" --no-pager -l > "${dir}/service-status.txt" 2>&1 || true
    wg show "${interface}" > "${dir}/wg-show.txt" 2>&1 || true
    ip -d addr show dev "${interface}" > "${dir}/ip-address.txt" 2>&1 || true
    ip route show table all > "${dir}/routes.txt" 2>&1 || true
    if ufw_installed; then
        ufw status numbered > "${dir}/ufw-status.txt" 2>&1 || true
    fi

    WG_LAST_MIGRATION_BACKUP="${dir}"
}

wireguard_migrate_existing_config() {
    local file="$1"
    wireguard_parse_existing_config "${file}" || return 1

    banner
    section "MIGRATE EXISTING WIREGUARD SERVER"

    echo "This converts an existing WireGuard server into manager-owned configuration."
    echo
    wireguard_show_discovered_config "${file}"
    echo
    echo "The existing server private key and peer public keys are kept."
    echo "Existing peers are imported, but their CLIENT private keys are not available"
    echo "on the server and therefore cannot be reconstructed."
    echo
    echo "For imported peers:"
    echo "  • live status and peer removal remain possible after migration"
    echo "  • QR code / complete client .conf cannot be generated"
    echo "  • newly created clients have full manager-generated configs and QR codes"
    echo

    if (( DISC_WG_COMPATIBLE != 1 )); then
        error "This existing configuration cannot be migrated automatically."
        printf '%-28s %s\n' "Reason:" "${DISC_WG_REASON}"
        info "You may still use read-only import."
        pause
        return
    fi

    if [[ "${DISC_WG_INTERFACE}" != "wg0" ]]; then
        error "Automatic migration currently supports interface wg0 only."
        info "Read-only import is still available for other WireGuard interfaces."
        pause
        return
    fi

    local endpoint dns egress
    endpoint="$(detect_public_ipv4)"
    echo
    echo "The public endpoint and client DNS are not stored in a WireGuard server config."
    echo "They are needed only for client configurations generated by the manager."
    echo
    read -r -p "Public WireGuard endpoint [${endpoint}]: " endpoint
    endpoint="${endpoint:-$(detect_public_ipv4)}"
    if ! valid_ipv4 "${endpoint}" && ! valid_hostname "${endpoint}"; then
        error "Endpoint must be an IPv4 address or DNS hostname."
        pause
        return
    fi

    read -r -p "DNS server for newly generated clients [${WG_DNS_DEFAULT}]: " dns
    dns="${dns:-${WG_DNS_DEFAULT}}"
    valid_ipv4 "${dns}" || { error "DNS must be an IPv4 address."; pause; return; }

    egress="$(detect_default_egress_interface)"
    [[ -n "${egress}" ]] || { error "Could not detect Internet egress interface."; pause; return; }

    echo
    section "MIGRATION PLAN"
    printf '%-28s %s\n' "Source config:" "${file}"
    printf '%-28s %s\n' "Interface:" "${DISC_WG_INTERFACE}"
    printf '%-28s %s\n' "VPN network:" "${DISC_WG_NETWORK}"
    printf '%-28s UDP %s\n' "Listen port:" "${DISC_WG_PORT}"
    printf '%-28s %s\n' "Existing peers:" "${#DISC_WG_PEER_PUBLIC_KEYS[@]}"
    printf '%-28s %s\n' "Internet egress:" "${egress}"
    echo
    echo "The manager will:"
    echo "  + create a timestamped backup of the existing WireGuard setup"
    echo "  + keep the existing server private key"
    echo "  + keep existing peer public keys / PSKs / /32 client IPs"
    echo "  + enable IPv4 forwarding"
    echo "  + replace wg0.conf with manager-owned full-tunnel NAT/forwarding rules"
    echo "  + remove matching legacy WireGuard NAT/FORWARD rules before restart"
    echo "  + add the WireGuard VPN network to routing table 220 when S2S policy routing is active"
    echo "  + restart wg-quick@wg0 briefly"
    echo "  + optionally manage the UFW WireGuard UDP rule"
    echo
    warn "Any custom PostUp/PostDown commands in the old config are NOT copied into the managed config."
    echo
    info "If the managed configuration fails to start, the manager automatically restores"
    info "the configuration backed up immediately before migration and restarts the old setup."
    echo
    confirm_yes_no "Migrate this WireGuard server to manager ownership?" "N" || return

    wireguard_backup_existing_config "${file}" "${DISC_WG_INTERFACE}" || {
        error "Could not create the migration backup. Nothing was changed."
        pause
        return
    }

    printf '%s\n' "${DISC_WG_PRIVATE_KEY}" > "${WG_SERVER_KEY}"
    chmod 600 "${WG_SERVER_KEY}"

    save_wireguard_server_state \
        "MANAGED" "${DISC_WG_INTERFACE}" "${DISC_WG_NETWORK}" "${DISC_WG_SERVER_IP}" \
        "${DISC_WG_PREFIX}" "${DISC_WG_PORT}" "${endpoint}" "${dns}" "${egress}" ""

    wireguard_import_existing_peers_readonly

    write_wireguard_sysctl || {
        error "Could not enable IPv4 forwarding."
        info "Backup: ${WG_LAST_MIGRATION_BACKUP}"
        pause
        return
    }

    ensure_wireguard_firewall_rule "${DISC_WG_PORT}" || {
        warn "Firewall step was cancelled or failed."
        info "The original WireGuard configuration backup is at:"
        echo "  ${WG_LAST_MIGRATION_BACKUP}"
        pause
        return
    }

    if wireguard_apply; then
        echo
        ok "Existing WireGuard server migrated successfully."
        printf '%-28s %s\n' "Backup:" "${WG_LAST_MIGRATION_BACKUP}"
        info "Existing clients keep their current keys and IPs."
        info "Only newly created clients can show a complete config / QR code in the manager."
    else
        error "Managed WireGuard configuration did not start."
        echo
        warn "Migration failed. Restoring the WireGuard configuration saved immediately before migration..."

        local backup_config="${WG_LAST_MIGRATION_BACKUP}/$(basename "${file}")"
        local rollback_ok=1

        if [[ -f "${backup_config}" ]]; then
            cp -a -- "${backup_config}" "${file}" || rollback_ok=0
            chmod 600 "${file}" 2>/dev/null || true
        else
            rollback_ok=0
        fi

        # Return manager metadata to the read-only state that existed before migration.
        save_wireguard_server_state \
            "IMPORTED" "${DISC_WG_INTERFACE}" "${DISC_WG_NETWORK}" "${DISC_WG_SERVER_IP}" \
            "${DISC_WG_PREFIX}" "${DISC_WG_PORT}" "${endpoint}" "${dns}" "${egress}" "${file}"
        wireguard_import_existing_peers_readonly
        rm -f "${WG_SERVER_KEY}" 2>/dev/null || true

        systemctl reset-failed "wg-quick@${DISC_WG_INTERFACE}" >/dev/null 2>&1 || true
        if (( rollback_ok == 1 )) && systemctl restart "wg-quick@${DISC_WG_INTERFACE}" >/tmp/s2s-manager-wireguard-rollback.log 2>&1; then
            ok "Rollback successful. The previous WireGuard configuration is active again."
            info "Manager state returned to IMPORTED / READ-ONLY."
            info "Backup kept at: ${WG_LAST_MIGRATION_BACKUP}"
        else
            error "Automatic rollback FAILED."
            info "Backup kept at: ${WG_LAST_MIGRATION_BACKUP}"
            info "Rollback log: /tmp/s2s-manager-wireguard-rollback.log"
            warn "WireGuard may currently be offline. Restore the backup manually before retrying."
        fi
    fi
    pause
}

wireguard_imported_server_menu() {
    while :; do
        load_wireguard_server || return

        banner
        section "IMPORTED WIREGUARD SERVER"

        echo "This WireGuard server is known to the manager but remains READ-ONLY."
        echo "The existing /etc/wireguard configuration and running interface are unchanged."
        echo
        wireguard_server_summary
        [[ -n "${WG_SOURCE_CONFIG}" ]] && printf '%-28s %s\n' "Source config:" "${WG_SOURCE_CONFIG}"
        echo
        echo "  [1] Migrate / take over imported WireGuard server"
        echo "  [2] Forget read-only import"
        echo "  [B] Back"
        echo

        local choice source="${WG_SOURCE_CONFIG}"
        read -r -p "Selection: " choice
        case "${choice}" in
            1)
                [[ -f "${source}" ]] || { error "Source configuration no longer exists."; pause; continue; }
                wireguard_migrate_existing_config "${source}"
                return
                ;;
            2)
                echo "This removes only the manager's read-only import metadata."
                echo "The existing WireGuard server is NOT changed."
                echo
                confirm_yes_no "Forget this imported WireGuard server?" "N" || continue
                rm -f "${WG_SERVER_STATE}"
                wireguard_clear_imported_clients
                ok "Read-only import removed. Existing WireGuard configuration was untouched."
                pause
                return
                ;;
            b|B|0|"") return ;;
            e|E) clear_screen; echo "Bye."; exit 0 ;;
            *) error "Invalid selection."; sleep 1 ;;
        esac
    done
}

wireguard_discovery_menu() {
    banner
    section "DISCOVER EXISTING WIREGUARD SERVER"

    echo "Scans /etc/wireguard for an existing manually configured WireGuard server."
    echo "Detection and read-only import do NOT change the running WireGuard setup."
    echo

    wireguard_select_existing_config || return
    local file="${SELECTED_WG_EXISTING}"

    banner
    section "EXISTING WIREGUARD CONFIGURATION"
    wireguard_show_discovered_config "${file}"
    echo
    echo "  [1] Import read-only"
    echo "      Show it in the manager without changing WireGuard."
    echo
    echo "  [2] Migrate / take over"
    echo "      Back up the existing setup and convert it to manager ownership."
    echo
    echo "  [B] Back"
    echo

    local choice
    read -r -p "Selection: " choice
    case "${choice}" in
        1)
            wireguard_import_existing_readonly "${file}"
            pause
            ;;
        2)
            wireguard_migrate_existing_config "${file}"
            ;;
    esac
}

wireguard_setup_new_server() {
    banner
    section "WIREGUARD SERVER SETUP"
    echo "Creates a simple IPv4 full-tunnel WireGuard VPN server."
    echo "Clients can reach this Debian server and use its Internet connection."
    echo "Automatic S2S remote-network access is NOT configured in this first version."
    echo

    if [[ -f "${WG_CONFIG}" && ! -f "${WG_SERVER_STATE}" ]]; then
        warn "An existing WireGuard configuration was found: ${WG_CONFIG}"
        echo "It will NOT be overwritten by the new-server setup."
        echo
        info "Use the WireGuard discovery/import function instead."
        pause
        return
    fi

    install_wireguard_packages || { error "Package installation failed."; pause; return; }

    local detected endpoint port network prefix base n server_ip dns egress
    detected="$(detect_public_ipv4)"
    read -r -p "Public WireGuard endpoint [${detected}]: " endpoint
    endpoint="${endpoint:-${detected}}"
    if ! valid_ipv4 "${endpoint}" && ! valid_hostname "${endpoint}"; then
        error "Endpoint must be an IPv4 address or DNS hostname."; pause; return
    fi

    read -r -p "WireGuard UDP listen port [${WG_PORT_DEFAULT}]: " port
    port="${port:-${WG_PORT_DEFAULT}}"
    [[ "${port}" =~ ^[0-9]+$ ]] && ((port>=1 && port<=65535)) || { error "Invalid port."; pause; return; }
    wireguard_udp_port_in_use "${port}" && { error "UDP port ${port} is already in use."; pause; return; }

    read -r -p "WireGuard VPN network [${WG_NETWORK_DEFAULT}]: " network
    network="${network:-${WG_NETWORK_DEFAULT}}"
    valid_cidr "${network}" || { error "Invalid IPv4 CIDR."; pause; return; }
    prefix="${network##*/}"
    [[ "${prefix}" == "24" ]] || { error "This first WireGuard version supports a /24 VPN network."; pause; return; }
    network="$(cidr_normalized "${network}")"
    if check_network_conflict "${network}" "" "${WG_INTERFACE_DEFAULT}"; then
        show_network_conflict "${network}"; pause; return
    fi
    base="${network%%/*}"; n="$(ipv4_to_int "${base}")"; server_ip="$(int_to_ipv4 "$((n+1))")"

    read -r -p "DNS server for clients [${WG_DNS_DEFAULT}]: " dns
    dns="${dns:-${WG_DNS_DEFAULT}}"
    valid_ipv4 "${dns}" || { error "DNS must be an IPv4 address."; pause; return; }

    egress="$(detect_default_egress_interface)"
    [[ -n "${egress}" ]] || { error "Could not detect Internet egress interface."; pause; return; }

    section "WIREGUARD SERVER PLAN"
    printf '%-28s %s\n' "Public endpoint:" "${endpoint}"
    printf '%-28s UDP %s\n' "Listen port:" "${port}"
    printf '%-28s %s\n' "VPN network:" "${network}"
    printf '%-28s %s/24\n' "Server VPN IP:" "${server_ip}"
    printf '%-28s %s\n' "Client DNS:" "${dns}"
    printf '%-28s %s\n' "Internet egress:" "${egress}"
    echo
    echo "Changes: IPv4 forwarding, wg0, Internet NAT, wg-quick service, optional UFW rule"
    echo "and a table 220 route for the WireGuard VPN network when S2S policy routing is active."
    echo
    confirm_yes_no "Create the WireGuard server now?" "N" || return

    wg genkey > "${WG_SERVER_KEY}" || { error "Key generation failed."; pause; return; }
    chmod 600 "${WG_SERVER_KEY}"
    save_wireguard_server_state "MANAGED" "${WG_INTERFACE_DEFAULT}" "${network}" "${server_ip}" "24" "${port}" "${endpoint}" "${dns}" "${egress}" ""
    write_wireguard_sysctl || { error "Could not enable IPv4 forwarding."; pause; return; }
    ensure_wireguard_firewall_rule "${port}" || { warn "Firewall setup cancelled/failed; server state was kept."; pause; return; }

    if wireguard_apply; then
        ok "WireGuard full-tunnel server is running."
        info "Next: create a client with 'Manage WireGuard clients'."
    else
        error "WireGuard could not be started."
    fi
    pause
}

wireguard_change_server_settings() {
    load_wireguard_server || return
    banner
    section "CHANGE WIREGUARD SERVER SETTINGS"
    echo "Changes the public endpoint, listen port or client DNS."
    echo "The VPN network and server key remain unchanged."
    echo
    local endpoint port dns old_port="${WG_PORT}"

    read -r -p "Public endpoint [${WG_ENDPOINT}]: " endpoint; endpoint="${endpoint:-${WG_ENDPOINT}}"
    if ! valid_ipv4 "${endpoint}" && ! valid_hostname "${endpoint}"; then error "Invalid endpoint."; pause; return; fi
    read -r -p "UDP listen port [${WG_PORT}]: " port; port="${port:-${WG_PORT}}"
    [[ "${port}" =~ ^[0-9]+$ ]] && ((port>=1 && port<=65535)) || { error "Invalid port."; pause; return; }
    [[ "${port}" != "${old_port}" ]] && wireguard_udp_port_in_use "${port}" && { error "UDP port ${port} is already in use."; pause; return; }
    read -r -p "Client DNS [${WG_DNS}]: " dns; dns="${dns:-${WG_DNS}}"
    valid_ipv4 "${dns}" || { error "Invalid DNS IPv4."; pause; return; }

    confirm_yes_no "Apply these settings?" "N" || return
    save_wireguard_server_state "MANAGED" "${WG_INTERFACE}" "${WG_NETWORK}" "${WG_SERVER_IP}" "${WG_PREFIX}" "${port}" "${endpoint}" "${dns}" "${WG_EGRESS_IF}" ""
    [[ "${port}" != "${old_port}" ]] && ensure_wireguard_firewall_rule "${port}" || true

    local id
    while read -r id; do [[ -n "${id}" ]] && wireguard_render_client_export "${id}" || true; done < <(list_wireguard_client_ids)
    wireguard_apply && ok "WireGuard settings applied." || error "WireGuard restart failed."
    pause
}

wireguard_server_menu() {
    if ! wireguard_server_known; then
        banner
        section "WIREGUARD SERVER"

        echo "Set up a new WireGuard server or detect an existing manual installation."
        echo
        if wireguard_existing_configs | grep -q .; then
            ok "Existing /etc/wireguard configuration detected."
        else
            info "No existing /etc/wireguard/*.conf configuration detected."
        fi
        echo
        echo "  [1] Create new manager-owned WireGuard server"
        echo "  [2] Discover / import existing WireGuard server"
        echo "  [B] Back"
        echo

        local first_choice
        read -r -p "Selection: " first_choice
        case "${first_choice}" in
            1) wireguard_setup_new_server ;;
            2) wireguard_discovery_menu ;;
        esac
        return
    fi

    if wireguard_server_imported; then
        wireguard_imported_server_menu
        return
    fi

    load_wireguard_server || return
    banner
    section "WIREGUARD SERVER"
    echo "Manages the local full-tunnel WireGuard VPN server."
    echo "Internet through this server is supported; automatic S2S access is not."
    echo
    wireguard_server_summary
    echo
    echo "  [1] Change endpoint / port / client DNS"
    echo "  [2] Change WireGuard VPN network"
    echo "      Keeps all keys and client host numbers in the new /24."
    echo "  [3] Restart / re-apply WireGuard server"
    echo "      Regenerates manager-owned wg0 configuration and routing/NAT rules."
    echo "  [4] Remove / reset WireGuard server"
    echo "      Creates a backup and allows a fresh setup."
    echo "  [B] Back"
    echo
    local c
    read -r -p "Selection: " c
    case "${c}" in
        1) wireguard_change_server_settings ;;
        2) wireguard_change_vpn_network ;;
        3) wireguard_apply && ok "WireGuard restarted." || error "Restart failed."; pause ;;
        4) wireguard_remove_managed_server ;;
    esac
}

wireguard_menu() {
    while :; do
        banner
        section "WIREGUARD"

        echo "Set up and manage the local full-tunnel WireGuard VPN server."
        echo
        echo "  [1] WireGuard server setup"
        echo "  [2] Manage WireGuard clients"
        echo "  [3] WireGuard status / diagnostics"
        echo "  [B] Back"
        echo "  [E] Exit"
        echo

        local c
        read -r -p "Selection: " c
        case "${c}" in
            1) wireguard_server_menu ;;
            2) wireguard_clients_menu ;;
            3) wireguard_status ;;
            b|B|0|"") return ;;
            e|E) clear_screen; echo "Bye."; exit 0 ;;
            *) error "Invalid selection."; sleep 1 ;;
        esac
    done
}

wireguard_add_client() {
    wireguard_server_managed || { warn "Configure WireGuard server first."; pause; return; }
    load_wireguard_server || return
    banner
    section "ADD WIREGUARD CLIENT"
    echo "Creates a full-tunnel IPv4 client (AllowedIPs = 0.0.0.0/0)."
    echo
    local name id base n=2 ip private public psk
    read -r -p "Client display name: " name
    [[ -n "${name}" ]] || { error "Client name required."; pause; return; }
    base="$(wireguard_safe_client_id "${name}")"; id="${base}"
    while [[ -e "$(wireguard_client_state_file "${id}")" ]]; do id="${base}-${n}"; ((n+=1)); done
    ip="$(wireguard_next_client_ip)" || { error "No free client IP."; pause; return; }
    private="$(wg genkey)" || return
    public="$(printf '%s' "${private}" | wg pubkey)" || return
    psk="$(wg genpsk)" || return
    {
        printf 'WG_CLIENT_ID=%q\n' "${id}"
        printf 'WG_CLIENT_NAME=%q\n' "${name}"
        printf 'WG_CLIENT_IP=%q\n' "${ip}"
        printf 'WG_CLIENT_PRIVATE_KEY=%q\n' "${private}"
        printf 'WG_CLIENT_PUBLIC_KEY=%q\n' "${public}"
        printf 'WG_CLIENT_PRESHARED_KEY=%q\n' "${psk}"
        printf 'WG_CLIENT_CREATED_AT=%q\n' "$(date -Is)"
    } > "$(wireguard_client_state_file "${id}")"
    chmod 600 "$(wireguard_client_state_file "${id}")"
    wireguard_render_client_export "${id}" || { error "Could not create client config."; pause; return; }
    wireguard_sync_peers_live || { error "Client saved, but live WireGuard update failed."; pause; return; }
    ok "WireGuard client created."
    printf '%-28s %s\n' "Client:" "${name}"
    printf '%-28s %s\n' "VPN IP:" "${ip}"
    printf '%-28s %s\n' "Config file:" "$(wireguard_client_export_file "${id}")"
    pause
}

select_wireguard_client() {
    local -a ids=(); local id i c
    while read -r id; do [[ -n "${id}" ]] && ids+=("${id}"); done < <(list_wireguard_client_ids)
    (( ${#ids[@]} > 0 )) || { warn "No WireGuard clients configured."; pause; return 1; }
    echo
    for i in "${!ids[@]}"; do
        load_wireguard_client "${ids[$i]}" || continue
        printf '  [%d] %-24s %s\n' "$((i+1))" "${WG_CLIENT_NAME}" "${WG_CLIENT_IP}"
    done
    echo; echo "B = Back"; read -r -p "Selection: " c
    [[ "${c}" =~ ^[0-9]+$ ]] && ((c>=1 && c<=${#ids[@]})) || return 1
    SELECTED_WG_CLIENT="${ids[$((c-1))]}"
}

wireguard_show_client_config() {
    select_wireguard_client || return
    load_wireguard_client "${SELECTED_WG_CLIENT}" || return
    if [[ -z "${WG_CLIENT_PRIVATE_KEY:-}" ]]; then
        banner
        section "WIREGUARD CLIENT CONFIGURATION"
        warn "This client was imported from the server-side WireGuard configuration."
        echo "Its private key is not stored on the server and cannot be reconstructed."
        echo "Therefore a complete client configuration cannot be generated."
        pause
        return
    fi
    wireguard_render_client_export "${SELECTED_WG_CLIENT}" || return
    banner; section "WIREGUARD CLIENT CONFIGURATION"
    warn "This configuration contains private key material."
    printf '%-28s %s\n' "Client:" "${WG_CLIENT_NAME}"
    printf '%-28s %s\n' "File:" "$(wireguard_client_export_file "${SELECTED_WG_CLIENT}")"
    echo; cat "$(wireguard_client_export_file "${SELECTED_WG_CLIENT}")"; pause
}

wireguard_show_client_qr() {
    select_wireguard_client || return
    local id="${SELECTED_WG_CLIENT}"
    load_wireguard_client "${id}" || return

    banner
    section "WIREGUARD CLIENT QR CODE"

    if [[ -z "${WG_CLIENT_PRIVATE_KEY:-}" ]]; then
        warn "This client was imported from the server-side WireGuard configuration."
        echo "Its private key is not stored on the server and cannot be reconstructed."
        echo "Therefore a complete client QR code cannot be generated."
        pause
        return
    fi

    local export_file="${WG_CLIENT_EXPORT_DIR}/${id}.conf"
    if [[ ! -f "${export_file}" ]]; then
        wireguard_render_client_export "${id}" || {
            error "Could not generate the WireGuard client configuration."
            pause
            return
        }
    fi

    if ! command -v qrencode >/dev/null 2>&1; then
        echo "The 'qrencode' package is required to display WireGuard client QR codes."
        echo "It is currently not installed."
        echo
        echo "Installing qrencode is optional and does not change the WireGuard server configuration."
        echo
        echo "  [1] Install qrencode"
        echo "  [B] Back"
        echo

        local choice
        read -r -p "Selection: " choice
        case "${choice}" in
            1)
                if ! command -v apt-get >/dev/null 2>&1; then
                    error "Automatic installation is only supported on systems with apt-get."
                    info "Install the 'qrencode' package manually and try again."
                    pause
                    return
                fi

                echo
                info "Installing qrencode..."
                if DEBIAN_FRONTEND=noninteractive apt-get update &&
                   DEBIAN_FRONTEND=noninteractive apt-get install -y qrencode; then
                    if ! command -v qrencode >/dev/null 2>&1; then
                        error "qrencode installation completed, but the command is still unavailable."
                        pause
                        return
                    fi
                    ok "qrencode installed successfully."
                    echo
                else
                    error "Could not install qrencode."
                    info "No WireGuard configuration was changed."
                    pause
                    return
                fi
                ;;
            b|B|0|"")
                return
                ;;
            *)
                error "Invalid selection."
                sleep 1
                return
                ;;
        esac
    fi

    echo "Scan with the WireGuard app. This QR code contains the client's private key."
    echo
    if ! qrencode -t ansiutf8 < "${export_file}"; then
        error "Could not render the WireGuard client QR code."
    fi
    pause
}


wireguard_rename_client() {
    select_wireguard_client || return
    local id="${SELECTED_WG_CLIENT}"
    load_wireguard_client "${id}" || return

    banner
    section "RENAME WIREGUARD CLIENT"

    echo "Changes only the client display name stored by the manager."
    echo "WireGuard keys, VPN IP, AllowedIPs and the live tunnel are not changed."
    echo
    printf '%-28s %s\n' "Current name:" "${WG_CLIENT_NAME}"
    printf '%-28s %s\n' "VPN IP:" "${WG_CLIENT_IP}"
    echo

    local new_name
    read -r -p "New client display name: " new_name
    [[ -n "${new_name}" ]] || {
        warn "No name entered. Nothing changed."
        pause
        return
    }

    if [[ "${new_name}" == "${WG_CLIENT_NAME}" ]]; then
        info "The new name is identical to the current name. Nothing changed."
        pause
        return
    fi

    local other
    while read -r other; do
        [[ -n "${other}" ]] || continue
        [[ "${other}" == "${id}" ]] && continue
        load_wireguard_client "${other}" || continue
        if [[ "${WG_CLIENT_NAME}" == "${new_name}" ]]; then
            error "Another WireGuard client already uses the display name '${new_name}'."
            pause
            return
        fi
    done < <(list_wireguard_client_ids)

    load_wireguard_client "${id}" || return

    local f
    f="$(wireguard_client_state_file "${id}")"

    {
        printf 'WG_CLIENT_ID=%q\n' "${WG_CLIENT_ID}"
        printf 'WG_CLIENT_NAME=%q\n' "${new_name}"
        printf 'WG_CLIENT_IP=%q\n' "${WG_CLIENT_IP}"
        printf 'WG_CLIENT_PRIVATE_KEY=%q\n' "${WG_CLIENT_PRIVATE_KEY}"
        printf 'WG_CLIENT_PUBLIC_KEY=%q\n' "${WG_CLIENT_PUBLIC_KEY}"
        printf 'WG_CLIENT_PRESHARED_KEY=%q\n' "${WG_CLIENT_PRESHARED_KEY}"
        printf 'WG_CLIENT_CREATED_AT=%q\n' "${WG_CLIENT_CREATED_AT}"
    } > "${f}"
    chmod 600 "${f}"

    # Managed client export remains technically unchanged, but refresh the comment/header.
    if [[ -n "${WG_CLIENT_PRIVATE_KEY:-}" && "${WG_MANAGEMENT}" == "MANAGED" ]]; then
        wireguard_render_client_export "${id}" || true
    fi

    ok "WireGuard client display name changed."
    printf '%-28s %s\n' "New name:" "${new_name}"
    pause
}


wireguard_show_client_export_instructions() {
    select_wireguard_client || return
    local id="${SELECTED_WG_CLIENT}"
    load_wireguard_client "${id}" || return

    banner
    section "EXPORT / TRANSFER WIREGUARD CLIENT"

    if [[ -z "${WG_CLIENT_PRIVATE_KEY:-}" ]]; then
        warn "This client was imported from an existing WireGuard server configuration."
        echo "Its private key is not stored on the server and cannot be reconstructed."
        echo "Therefore no complete client configuration file is available for export."
        pause
        return
    fi

    wireguard_render_client_export "${id}" || {
        error "Could not generate the WireGuard client configuration."
        pause
        return
    }

    load_wireguard_server || return

    local export_file
    export_file="$(wireguard_client_export_file "${id}")"

    local ssh_port="22"
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        ssh_port="$(awk '{print $4}' <<< "${SSH_CONNECTION}")"
    fi
    [[ "${ssh_port}" =~ ^[0-9]+$ ]] || ssh_port="22"

    local ssh_host="${WG_ENDPOINT}"
    local ssh_user="root"

    printf '%-28s %s\n' "Client:" "${WG_CLIENT_NAME}"
    printf '%-28s %s\n' "VPN IP:" "${WG_CLIENT_IP}"
    printf '%-28s %s\n' "Config file:" "${export_file}"
    printf '%-28s %s\n' "SSH server:" "${ssh_host}"
    printf '%-28s %s\n' "SSH port:" "${ssh_port}"
    echo

    echo "Download the configuration FROM your computer."
    echo "The server does not need access to your computer."
    echo

    section "MACOS / LINUX"
    echo "Run this command in Terminal:"
    echo
    if [[ "${ssh_port}" == "22" ]]; then
        printf 'scp %s@%s:%q ~/Downloads/\n' "${ssh_user}" "${ssh_host}" "${export_file}"
    else
        printf 'scp -P %s %s@%s:%q ~/Downloads/\n' "${ssh_port}" "${ssh_user}" "${ssh_host}" "${export_file}"
    fi
    echo
    echo "The file will be saved in your Downloads folder."

    echo
    section "WINDOWS POWERSHELL"
    echo "Modern Windows versions can use the built-in OpenSSH scp command when"
    echo "the 'OpenSSH Client' optional feature is installed."
    echo
    echo "Run this command in PowerShell:"
    echo
    if [[ "${ssh_port}" == "22" ]]; then
        printf 'scp %s@%s:%s "$HOME\\Downloads\\"\n' "${ssh_user}" "${ssh_host}" "${export_file}"
    else
        printf 'scp -P %s %s@%s:%s "$HOME\\Downloads\\"\n' "${ssh_port}" "${ssh_user}" "${ssh_host}" "${export_file}"
    fi
    echo
    echo "If Windows reports that 'scp' is unknown, install the Windows"
    echo "'OpenSSH Client' optional feature or use an SFTP client such as WinSCP."
    echo
    printf 'SFTP server:                %s\n' "${ssh_host}"
    printf 'SFTP port:                  %s\n' "${ssh_port}"
    printf 'SFTP user:                  %s\n' "${ssh_user}"
    printf 'Remote file:                %s\n' "${export_file}"

    echo
    warn "The exported .conf file contains the client's private WireGuard key"
    warn "and may also contain a preshared key. Treat it like a password."
    pause
}

wireguard_remove_client() {
    select_wireguard_client || return
    load_wireguard_client "${SELECTED_WG_CLIENT}" || return
    banner; section "REMOVE WIREGUARD CLIENT"
    printf '%-28s %s\n' "Client:" "${WG_CLIENT_NAME}"
    printf '%-28s %s\n' "VPN IP:" "${WG_CLIENT_IP}"
    echo; confirm_yes_no "Remove this client from WireGuard?" "N" || return
    rm -f "$(wireguard_client_state_file "${SELECTED_WG_CLIENT}")" "$(wireguard_client_export_file "${SELECTED_WG_CLIENT}")"
    wireguard_sync_peers_live && ok "Client removed." || error "Client removed from state, but live WireGuard update failed."
    pause
}

wireguard_clients_menu() {
    wireguard_server_known || {
        banner
        section "WIREGUARD CLIENTS"
        warn "Configure or import a WireGuard server first."
        pause
        return
    }

    while :; do
        load_wireguard_server || return

        banner
        section "WIREGUARD CLIENTS"

        if [[ "${WG_MANAGEMENT}" == "IMPORTED" ]]; then
            echo "The WireGuard server is imported READ-ONLY."
            echo "Existing peers are shown below, but client changes require migration."
        else
            echo "Manage full-tunnel WireGuard clients."
        fi
        echo

        local id count=0 dump peer handshake now age hs type
        dump="$(wg show "${WG_INTERFACE}" dump 2>/dev/null || true)"
        now="$(date +%s)"

        printf '%-4s %-24s %-15s %-12s %-18s\n' "#" "Name" "VPN IP" "Type" "Handshake"
        printf '%-4s %-24s %-15s %-12s %-18s\n' "──" "──────────────────────" "──────────────" "──────────" "────────────────"

        while read -r id; do
            [[ -n "${id}" ]] || continue
            load_wireguard_client "${id}" || continue
            ((count += 1))
            [[ -n "${WG_CLIENT_PRIVATE_KEY:-}" ]] && type="MANAGED" || type="IMPORTED"

            peer="$(awk -F'\t' -v p="${WG_CLIENT_PUBLIC_KEY}" '$1==p {print; exit}' <<< "${dump}")"
            handshake=0
            [[ -n "${peer}" ]] && handshake="$(cut -f5 <<< "${peer}")"
            if [[ "${handshake}" =~ ^[0-9]+$ ]] && (( handshake > 0 )); then
                age=$((now - handshake))
                hs="$(human_duration "${age}") ago"
            else
                hs="Never"
            fi

            printf '%-4s %-24s %-15s %-12s %-18s\n' \
                "${count}" "${WG_CLIENT_NAME:0:24}" "${WG_CLIENT_IP}" "${type}" "${hs}"
        done < <(list_wireguard_client_ids)

        (( count == 0 )) && printf '%s\n' "     No WireGuard clients configured."
        echo

        if [[ "${WG_MANAGEMENT}" == "IMPORTED" ]]; then
            info "Imported peers are read-only."
            info "Their client private keys are not stored on the server, so complete configs/QR codes cannot be recreated."
            info "Use 'WireGuard server setup' -> 'Migrate / take over imported WireGuard server' to manage the server."
            pause
            return
        fi

        echo "  [1] Add client"
        echo "  [2] Show client configuration"
        echo "  [3] Show client QR code"
        echo "  [4] Rename client display name"
        echo "  [5] Export / transfer client configuration"
        echo "  [6] Remove client"
        echo "  [B] Back"
        echo
        local c
        read -r -p "Selection: " c
        case "${c}" in
            1) wireguard_add_client ;;
            2) wireguard_show_client_config ;;
            3) wireguard_show_client_qr ;;
            4) wireguard_rename_client ;;
            5) wireguard_show_client_export_instructions ;;
            6) wireguard_remove_client ;;
            b|B|0|"") return ;;
            e|E) clear_screen; echo "Bye."; exit 0 ;;
        esac
        # Child actions pause themselves. Redraw this WireGuard client menu afterwards.
    done
}

wireguard_status() {
    banner; section "WIREGUARD STATUS / DIAGNOSTICS"
    echo "Read-only status, handshakes and traffic counters."
    echo
    wireguard_server_known || { warn "No WireGuard server is configured/imported in the manager."; pause; return; }
    load_wireguard_server || return
    wireguard_server_summary
    printf '%-28s %s\n' "IPv4 forwarding:" "$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo unknown)"

    if wireguard_table220_active; then
        if wireguard_table220_route_ok; then
            ok "Routing table 220: ${WG_NETWORK} -> ${WG_INTERFACE}"
        else
            error "Routing table 220 is active, but ${WG_NETWORK} is not routed to ${WG_INTERFACE}."
            info "Full-tunnel return traffic may be sent to the wrong interface."
        fi
    else
        info "Routing table 220 policy is not active; no WireGuard table 220 route is required."
    fi

    echo; section "CLIENTS"
    local dump now id peer h rx tx age hs
    dump="$(wg show "${WG_INTERFACE}" dump 2>/dev/null || true)"
    now="$(date +%s)"
    printf '%-22s %-15s %-18s %-12s %-12s\n' "Name" "VPN IP" "Handshake" "RX" "TX"
    while read -r id; do
        [[ -n "${id}" ]] || continue
        load_wireguard_client "${id}" || continue
        peer="$(awk -F'\t' -v p="${WG_CLIENT_PUBLIC_KEY}" '$1==p{print;exit}' <<< "${dump}")"
        h=0; rx=0; tx=0
        if [[ -n "${peer}" ]]; then h="$(cut -f5 <<< "${peer}")"; rx="$(cut -f6 <<< "${peer}")"; tx="$(cut -f7 <<< "${peer}")"; fi
        if [[ "${h}" =~ ^[0-9]+$ ]] && ((h>0)); then age=$((now-h)); hs="$(human_duration "${age}") ago"; else hs="Never"; fi
        printf '%-22s %-15s %-18s %-12s %-12s\n' "${WG_CLIENT_NAME:0:22}" "${WG_CLIENT_IP}" "${hs}" "$(human_bytes "${rx}")" "$(human_bytes "${tx}")"
    done < <(list_wireguard_client_ids)
    echo; section "LIVE WG OUTPUT"
    wg show "${WG_INTERFACE}" 2>/dev/null || warn "WireGuard interface is not active."
    echo
    if ufw_installed; then
        wireguard_rule_exists "${WG_PORT}" && ok "UFW WireGuard rule present (UDP ${WG_PORT})." || warn "Managed UFW WireGuard rule missing."
    else
        info "UFW not installed; check provider firewall for UDP ${WG_PORT}."
    fi
    pause
}


server_memory_health() {
    local available="$1" total="$2"
    (( total > 0 )) || { printf 'unknown'; return; }
    if (( available < 268435456 || available * 100 / total < 5 )); then
        printf 'critical'
    elif (( available < 536870912 || available * 100 / total < 15 )); then
        printf 'warning'
    else
        printf 'ok'
    fi
}

server_disk_health() {
    local percent="$1"
    if (( percent >= 90 )); then
        printf 'critical'
    elif (( percent >= 80 )); then
        printf 'warning'
    else
        printf 'ok'
    fi
}

detect_dmi_memory_bytes() {
    command_available dmidecode || return 1
    dmidecode --type memory 2>/dev/null | awk '
        /^[[:space:]]*Size:[[:space:]]+[0-9]+[[:space:]]+(MB|GB|TB)$/ {
            value=$2; unit=$3
            if (unit == "MB") total += value * 1024 * 1024
            else if (unit == "GB") total += value * 1024 * 1024 * 1024
            else if (unit == "TB") total += value * 1024 * 1024 * 1024 * 1024
        }
        END { if (total > 0) printf "%.0f", total }
    '
}

show_server_hardware_status() {
    local os kernel architecture vendor model virtualization hypervisor_vendor virtualization_type
    local cpu_model vcpus mem_total_kb mem_available_kb mem_total mem_available mem_used memory_health
    local swap_total_kb swap_total dmi_memory root_data root_total_kb root_used_kb root_available_kb
    local root_percent root_total root_used root_available disk_health uptime_seconds load

    section "SERVER / VIRTUAL MACHINE"

    os="$(awk -F= '$1=="PRETTY_NAME"{v=substr($0,index($0,"=")+1); gsub(/^"|"$/, "", v); print v; exit}' /etc/os-release 2>/dev/null)"
    kernel="$(uname -r 2>/dev/null || echo unknown)"
    architecture="$(uname -m 2>/dev/null || echo unknown)"
    vendor="$(sed -n '1{s/^[[:space:]]*//;s/[[:space:]]*$//;p;}' /sys/class/dmi/id/sys_vendor 2>/dev/null)"
    model="$(sed -n '1{s/^[[:space:]]*//;s/[[:space:]]*$//;p;}' /sys/class/dmi/id/product_name 2>/dev/null)"
    virtualization="$(systemd-detect-virt 2>/dev/null || true)"
    [[ -n "${virtualization}" ]] || virtualization="unknown"
    hypervisor_vendor="$(lscpu 2>/dev/null | awk -F: '/^Hypervisor vendor:/{gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; exit}')"
    virtualization_type="$(lscpu 2>/dev/null | awk -F: '/^Virtualization type:/{gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; exit}')"

    printf '%-28s %s\n' "Provider / DMI vendor:" "${vendor:-unknown}"
    printf '%-28s %s\n' "Virtual hardware:" "${model:-unknown}"
    printf '%-28s %s\n' "Detected virtualization:" "${virtualization}"
    [[ -n "${hypervisor_vendor}" ]] && printf '%-28s %s\n' "Hypervisor signature:" "${hypervisor_vendor}"
    [[ -n "${virtualization_type}" ]] && printf '%-28s %s\n' "Virtualization type:" "${virtualization_type}"
    if [[ "${virtualization}" != "none" && "${virtualization}" != "unknown" ]]; then
        printf '%-28s %s\n' "Host management platform:" "not detectable from guest"
    fi
    printf '%-28s %s\n' "Operating system:" "${os:-unknown}"
    printf '%-28s %s\n' "Kernel:" "${kernel}"
    printf '%-28s %s\n' "Architecture:" "${architecture}"

    echo
    section "CPU"
    cpu_model="$(awk -F: '/^(model name|Hardware)[[:space:]]*:/{gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; exit}' /proc/cpuinfo 2>/dev/null)"
    vcpus="$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)"
    [[ "${vcpus}" =~ ^[0-9]+$ ]] || vcpus="$(awk '/^processor[[:space:]]*:/{count++} END{print count+0}' /proc/cpuinfo 2>/dev/null)"
    printf '%-28s %s\n' "CPU model exposed to guest:" "${cpu_model:-unknown}"
    printf '%-28s %s\n' "Virtual CPUs online:" "${vcpus:-unknown}"
    info "The exposed CPU model may be generic and need not identify the physical host CPU."

    echo
    section "MEMORY"
    mem_total_kb="$(awk '$1=="MemTotal:"{print $2}' /proc/meminfo 2>/dev/null)"
    mem_available_kb="$(awk '$1=="MemAvailable:"{print $2}' /proc/meminfo 2>/dev/null)"
    swap_total_kb="$(awk '$1=="SwapTotal:"{print $2}' /proc/meminfo 2>/dev/null)"
    mem_total=$(( ${mem_total_kb:-0} * 1024 ))
    mem_available=$(( ${mem_available_kb:-0} * 1024 ))
    mem_used=$(( mem_total > mem_available ? mem_total - mem_available : 0 ))
    swap_total=$(( ${swap_total_kb:-0} * 1024 ))
    dmi_memory="$(detect_dmi_memory_bytes 2>/dev/null || true)"
    [[ "${dmi_memory}" =~ ^[0-9]+$ ]] && printf '%-28s %s\n' "DMI assigned memory:" "$(human_bytes "${dmi_memory}")"
    printf '%-28s %s\n' "Linux usable memory:" "$(human_bytes "${mem_total}")"
    printf '%-28s %s\n' "Currently used:" "$(human_bytes "${mem_used}")"
    printf '%-28s %s\n' "Currently available:" "$(human_bytes "${mem_available}")"
    printf '%-28s %s\n' "Swap configured:" "$(human_bytes "${swap_total}")"
    memory_health="$(server_memory_health "${mem_available}" "${mem_total}")"
    case "${memory_health}" in
        critical) error "Available memory is critically low." ;;
        warning) warn "Available memory is low." ;;
        ok) ok "Available memory is healthy." ;;
        *) warn "Memory health could not be evaluated." ;;
    esac
    (( swap_total > 0 )) && ok "Swap is configured." || warn "No swap is configured; small VPS instances have less protection against memory spikes."
    info "Booked/advertised RAM is not reliably available inside the guest; Linux usable memory excludes reserved regions."

    echo
    section "ROOT FILESYSTEM"
    root_data="$(df -Pk / 2>/dev/null | awk 'NR==2{gsub(/%/, "", $5); print $2, $3, $4, $5}')"
    read -r root_total_kb root_used_kb root_available_kb root_percent <<< "${root_data}"
    root_total=$(( ${root_total_kb:-0} * 1024 ))
    root_used=$(( ${root_used_kb:-0} * 1024 ))
    root_available=$(( ${root_available_kb:-0} * 1024 ))
    root_percent="${root_percent:-0}"
    printf '%-28s %s\n' "Size:" "$(human_bytes "${root_total}")"
    printf '%-28s %s (%s%%)\n' "Used:" "$(human_bytes "${root_used}")" "${root_percent}"
    printf '%-28s %s\n' "Available:" "$(human_bytes "${root_available}")"
    disk_health="$(server_disk_health "${root_percent}")"
    case "${disk_health}" in
        critical) error "Root filesystem usage is critical (90% or more)." ;;
        warning) warn "Root filesystem usage is high (80% or more)." ;;
        *) ok "Root filesystem usage is healthy." ;;
    esac

    echo
    section "RUNTIME"
    uptime_seconds="$(awk '{print int($1)}' /proc/uptime 2>/dev/null)"
    load="$(awk '{print $1 " / " $2 " / " $3}' /proc/loadavg 2>/dev/null)"
    printf '%-28s %s\n' "Uptime:" "$(human_duration "${uptime_seconds:-0}")"
    printf '%-28s %s\n' "Load average (1/5/15m):" "${load:-unknown}"
}

show_system_status() {
    banner
    show_server_hardware_status

    echo
    show_preflight embedded || true

    echo
    section "POLICY ROUTING TABLE 220"
    if [[ -n "$(table220_default_route)" ]]; then
        error "Table 220 contains a default route that can shadow local Docker/VM networks."
        printf '    %s\n' "$(table220_default_route)"
        info "Re-apply an installed tunnel to regenerate its explicit routes after reviewing the configuration."
    else
        ok "Table 220 has no catch-all default route; unmatched traffic falls through to main."
    fi

    echo
    section "MANAGED TUNNELS"
    show_existing_tunnels

    echo
    section "STRONGSWAN"
    if systemctl is-active --quiet strongswan 2>/dev/null; then
        ok "strongSwan active"
    else
        warn "strongSwan not active"
    fi

    if command_available swanctl; then
        echo
        swanctl_clean swanctl --list-sas || true
    fi

    echo
    section "FIREWALL"
    if ufw_installed; then
        ufw status | grep -E 'S2S Manager|500/udp|4500/udp|esp' || true
    else
        info "Local UFW not installed (optional)"
        echo "External/provider firewall can be used instead."
        echo "Required for IPsec: UDP 500 and UDP 4500"
    fi

    echo
    section "SAMBA"
    if samba_installed; then
        samba_service_active && ok "Samba installed and smbd active" || warn "Samba installed but smbd not active"
        printf '%-28s %s\n' "Effective shares:" "$(samba_effective_share_names 2>/dev/null | wc -l)"
        printf '%-28s %s\n' "Manager-owned shares:" "$(find "${SAMBA_SHARE_DIR}" -maxdepth 1 -type f -name '*.share' 2>/dev/null | wc -l)"
    else
        info "Samba not installed (optional)"
    fi

    pause
}


# ==============================================================================
# Tunnel diagnostics
# ==============================================================================

human_bytes() {
    local bytes="${1:-0}"

    if ! [[ "${bytes}" =~ ^[0-9]+$ ]]; then
        printf '%s' "${bytes}"
        return
    fi

    if (( bytes >= 1073741824 )); then
        awk -v b="${bytes}" 'BEGIN { printf "%.2f GiB", b/1073741824 }'
    elif (( bytes >= 1048576 )); then
        awk -v b="${bytes}" 'BEGIN { printf "%.2f MiB", b/1048576 }'
    elif (( bytes >= 1024 )); then
        awk -v b="${bytes}" 'BEGIN { printf "%.2f KiB", b/1024 }'
    else
        printf '%s B' "${bytes}"
    fi
}


human_duration() {
    local seconds="${1:-0}"
    local d h m s

    [[ "${seconds}" =~ ^[0-9]+$ ]] || { printf '%s' "${seconds}"; return; }

    d=$((seconds / 86400))
    h=$(((seconds % 86400) / 3600))
    m=$(((seconds % 3600) / 60))
    s=$((seconds % 60))

    if (( d > 0 )); then
        printf '%dd %02dh %02dm %02ds' "${d}" "${h}" "${m}" "${s}"
    elif (( h > 0 )); then
        printf '%dh %02dm %02ds' "${h}" "${m}" "${s}"
    elif (( m > 0 )); then
        printf '%dm %02ds' "${m}" "${s}"
    else
        printf '%ds' "${s}"
    fi
}

get_tunnel_sa_output() {
    local name="$1"
    local conn
    conn="$(tunnel_connection_name "${name}")" || return 1

    swanctl_clean swanctl --list-sas 2>/dev/null | \
        awk -v c="${conn}:" '
            $0 ~ "^" c {show=1}
            show {print}
            show && /^[^[:space:]]/ && $0 !~ "^" c {exit}
        '
}


get_tunnel_connected_since_epoch() {
    local name="$1"
    local conn
    conn="$(tunnel_connection_name "${name}")" || return 1
    local line epoch msg id
    local history_known=0
    local connected_since=""
    local active_count=0
    declare -A active_ike=()

    # We only report a continuous connection start if the retained journal
    # contains a reliable anchor. A strongSwan service start is such an anchor:
    # no IKE SA can predate the daemon start.
    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue

        epoch="${line%% *}"
        epoch="${epoch%%.*}"
        [[ "${epoch}" =~ ^[0-9]+$ ]] || continue
        msg="${line#* }"

        if [[ "${msg}" == *"Started strongswan.service"* ]] || \
           [[ "${msg}" == *"Started strongSwan IPsec"* ]]; then
            active_ike=()
            active_count=0
            connected_since=""
            history_known=1
            continue
        fi

        if [[ "${msg}" =~ IKE_SA[[:space:]]+${conn}\[([0-9]+)\][[:space:]]+established[[:space:]]+between ]]; then
            id="${BASH_REMATCH[1]}"
            if [[ -z "${active_ike[$id]+x}" ]]; then
                if (( active_count == 0 )) && (( history_known == 1 )); then
                    connected_since="${epoch}"
                fi
                active_ike[$id]=1
                ((active_count += 1))
            fi
            continue
        fi

        if [[ "${msg}" =~ deleting[[:space:]]+IKE_SA[[:space:]]+${conn}\[([0-9]+)\] ]]; then
            id="${BASH_REMATCH[1]}"
            if [[ -n "${active_ike[$id]+x}" ]]; then
                unset 'active_ike[$id]'
                ((active_count -= 1))
                if (( active_count == 0 )); then
                    connected_since=""
                fi
            fi
            continue
        fi
    done < <(journalctl -u strongswan --no-pager -o short-unix 2>/dev/null)

    # If the currently active SA is visible but we have no anchored start in
    # the retained journal, do not guess. Let the caller report that it cannot
    # be determined from logs.
    if (( history_known == 1 )) && (( active_count > 0 )) && [[ -n "${connected_since}" ]]; then
        printf '%s' "${connected_since}"
        return 0
    fi

    return 1
}

show_tunnel_diagnostics() {
    banner
    section "TUNNEL DIAGNOSTICS"

    echo "Checks the selected tunnel without changing its configuration."
    echo "It shows manager/install state, strongSwan and VTI status, table 220 routes"
    echo "and the current IKE/CHILD SA connection state."
    echo "Optional tests can ping the remote VTI address, analyze uptime or show recent logs."
    echo

    select_tunnel || return

    local name="${SELECTED_TUNNEL}"
    load_tunnel "${name}" || return

    local service
    if [[ "${MANAGEMENT}" == "IMPORTED" && -n "${SOURCE_SERVICE}" ]]; then
        service="${SOURCE_SERVICE}"
    else
        service="$(managed_service_name "${name}")"
    fi

    printf '%-28s %s\n' "Display name:" "${DISPLAY_NAME}"
    printf '%-28s %s\n' "Internal name:" "${NAME}"
    printf '%-28s %s\n' "Peer type:" "$(peer_type_label "${PEER_TYPE}")"
    actual_install_state "${name}" || true
    printf '%-28s %s\n' "Management:" "$(actual_install_state_label "${ACTUAL_INSTALL_STATE}")"
    if [[ "${ACTUAL_INSTALL_STATE}" == "PARTIAL" ]]; then
        printf '%-28s %s\n' "State details:" "${ACTUAL_INSTALL_DETAIL}"
    fi
    printf '%-28s %s\n' "VTI interface:" "${VTI_INTERFACE}"
    printf '%-28s %s\n' "Local Debian VTI IP:" "${DEBIAN_VTI_IP}"
    if [[ "${PEER_TYPE}" == "debian" ]]; then
        printf '%-28s %s\n' "Remote Debian VTI IP:" "${UNIFI_VTI_IP}"
    else
        printf '%-28s %s\n' "UniFi VTI IP:" "${UNIFI_VTI_IP}"
    fi
    printf '%-28s %s\n' "Tunnel network:" "${VTI_NETWORK}"
    printf '%-28s %s\n' "Authentication ID:" "${AUTH_ID}"

    echo
    section "SERVICE / INTERFACE"

    if systemctl is-active --quiet strongswan 2>/dev/null; then
        ok "strongSwan: active"
    else
        error "strongSwan: inactive"
    fi

    if systemctl is-active --quiet "${service}" 2>/dev/null; then
        ok "${service}: active"
    else
        warn "${service}: not active"
    fi

    if ip link show "${VTI_INTERFACE}" >/dev/null 2>&1; then
        ok "${VTI_INTERFACE}: present"
        local current_addr
        current_addr="$(ip -4 -o addr show dev "${VTI_INTERFACE}" 2>/dev/null | awk '{print $4}' | head -1)"
        printf '%-28s %s\n' "Current VTI address:" "${current_addr:-none}"
    else
        error "${VTI_INTERFACE}: missing"
    fi

    echo
    section "ROUTING"

    local route test_ip lookup
    printf '%-28s %s\n' "Table:" "220"
    while read -r route; do
        [[ -z "${route}" ]] && continue

        if [[ "${route}" == "${VTI_NETWORK}" ]]; then
            test_ip="${UNIFI_VTI_IP}"
        else
            test_ip="${route%%/*}"
        fi

        lookup="$(ip route get "${test_ip}" 2>/dev/null || true)"

        if grep -q "dev ${VTI_INTERFACE}" <<< "${lookup}" && \
           grep -q "table 220" <<< "${lookup}"; then
            ok "${route} -> ${VTI_INTERFACE}"
        else
            error "${route} is not routed via ${VTI_INTERFACE} / table 220"
            [[ -n "${lookup}" ]] && printf '    Kernel lookup: %s\n' "${lookup}"
        fi
    done < <(printf '%s\n' "${VTI_NETWORK}"; read_routes "${name}")

    echo
    section "IPSEC STATUS"

    local sa
    sa="$(get_tunnel_sa_output "${name}")"

    if [[ -z "${sa}" ]]; then
        warn "No active IKE/CHILD SA found."
        printf '%-28s %s\n' "Connection:" "NOT CONNECTED"
    else
        if grep -q 'ESTABLISHED' <<< "${sa}"; then
            ok "IKE: ESTABLISHED"
        else
            warn "IKE: not established"
        fi

        if grep -q 'INSTALLED' <<< "${sa}"; then
            ok "CHILD_SA: INSTALLED"
        else
            warn "CHILD_SA: not installed"
        fi

        if grep -q 'TUNNEL-in-UDP' <<< "${sa}"; then
            ok "Transport: ESP-in-UDP / NAT-T"
        elif grep -q 'TUNNEL' <<< "${sa}"; then
            info "Transport: native ESP tunnel"
        fi

        local established ike_age_seconds child_installed child_age_seconds

        established="$(grep -m1 -oE 'established [0-9]+s ago' <<< "${sa}" || true)"
        if [[ -n "${established}" ]]; then
            ike_age_seconds="$(grep -oE '[0-9]+' <<< "${established}" | head -1)"
            printf '%-28s %s\n' "Current IKE SA age:" "$(human_duration "${ike_age_seconds}")"
        fi

        child_installed="$(grep -m1 -oE 'installed [0-9]+s ago' <<< "${sa}" || true)"
        if [[ -n "${child_installed}" ]]; then
            child_age_seconds="$(grep -oE '[0-9]+' <<< "${child_installed}" | head -1)"
            printf '%-28s %s\n' "Current CHILD SA age:" "$(human_duration "${child_age_seconds}")"
        fi

        local in_bytes out_bytes in_packets out_packets
        in_bytes="$(awk '/^[[:space:]]+in[[:space:]]/ {for(i=1;i<=NF;i++) if($i=="bytes,"){print $(i-1); exit}}' <<< "${sa}")"
        out_bytes="$(awk '/^[[:space:]]+out[[:space:]]/ {for(i=1;i<=NF;i++) if($i=="bytes,"){print $(i-1); exit}}' <<< "${sa}")"
        in_packets="$(awk '/^[[:space:]]+in[[:space:]]/ {for(i=1;i<=NF;i++) if($i=="packets," || $i=="packets"){print $(i-1); exit}}' <<< "${sa}")"
        out_packets="$(awk '/^[[:space:]]+out[[:space:]]/ {for(i=1;i<=NF;i++) if($i=="packets," || $i=="packets"){print $(i-1); exit}}' <<< "${sa}")"

        [[ -n "${in_bytes}" ]] && printf '%-28s %s (%s packets)\n' "Traffic IN:" "$(human_bytes "${in_bytes}")" "${in_packets:-0}"
        [[ -n "${out_bytes}" ]] && printf '%-28s %s (%s packets)\n' "Traffic OUT:" "$(human_bytes "${out_bytes}")" "${out_packets:-0}"
    fi

    while :; do
        echo
        if [[ "${PEER_MODE}" == "dns" ]]; then
        section "DYNAMIC DNS"
        dns_peer_status "${name}" || true
        printf '%-28s %s\n' "Hostname:" "${PEER_ADDRESS}"
        case "${DNS_STATUS}" in
            CURRENT)
                ok "Dynamic DNS endpoint is current"
                printf '%-28s %s\n' "Current DNS IPv4:" "${DNS_CURRENT_IP}"
                printf '%-28s %s\n' "VTI remote IPv4:" "${DNS_VTI_IP}"
                ;;
            OUTDATED)
                error "Dynamic DNS endpoint is outdated"
                printf '%-28s %s\n' "Current DNS IPv4:" "${DNS_CURRENT_IP}"
                printf '%-28s %s\n' "VTI remote IPv4:" "${DNS_VTI_IP}"
                echo
                warn "Run Re-apply tunnel configuration to update the VTI endpoint."
                ;;
            UNRESOLVED|MULTIPLE|CHECK_UNAVAILABLE|NO_VTI)
                error "Dynamic DNS check failed"
                printf '%-28s %s\n' "Reason:" "${DNS_STATUS_DETAIL}"
                [[ -n "${DNS_CURRENT_IP}" ]] && printf '%-28s %s\n' "Current DNS IPv4:" "${DNS_CURRENT_IP}"
                [[ -n "${DNS_VTI_IP}" ]] && printf '%-28s %s\n' "VTI remote IPv4:" "${DNS_VTI_IP}"
                ;;
        esac
    fi

    section "OPTIONAL TESTS"

        if [[ "${PEER_TYPE}" == "debian" ]]; then
            echo "  [1] Ping remote Debian VTI address"
        else
            echo "  [1] Ping UniFi VTI address"
        fi
        echo "      Test connectivity to ${UNIFI_VTI_IP}"
        echo
        echo "  [2] Analyze connection uptime"
        echo "      Determine continuous connection time from strongSwan logs."
        echo "      This may take several seconds."
        echo
        echo "  [3] Show recent strongSwan logs"
        echo
        echo "  [B] Back"
        echo "  [E] Exit"
        echo

        local choice connected_since_epoch now_epoch connected_for_seconds
        read -r -p "Selection: " choice

        case "${choice}" in
            1)
                echo
                section "CONNECTIVITY TEST"
                if [[ "${PEER_TYPE}" == "debian" ]]; then
                    echo "Pinging remote Debian VTI address ${UNIFI_VTI_IP}..."
                else
                    echo "Pinging UniFi VTI address ${UNIFI_VTI_IP}..."
                fi
                echo

                if ping -c 3 -W 2 "${UNIFI_VTI_IP}" >/tmp/s2s-manager-diag-ping.log 2>&1; then
                    ok "Ping to ${UNIFI_VTI_IP}: SUCCESS"
                    tail -2 /tmp/s2s-manager-diag-ping.log
                else
                    error "Ping to ${UNIFI_VTI_IP}: FAILED"
                    cat /tmp/s2s-manager-diag-ping.log
                fi
                pause
                ;;
            2)
                echo
                section "CONNECTION UPTIME"
                echo "Analyzing strongSwan connection history..."
                echo "This may take several seconds."
                echo

                connected_since_epoch="$(get_tunnel_connected_since_epoch "${name}" 2>/dev/null || true)"
                if [[ -n "${connected_since_epoch}" ]]; then
                    now_epoch="$(date +%s)"
                    connected_for_seconds=$((now_epoch - connected_since_epoch))
                    if (( connected_for_seconds >= 0 )); then
                        printf '%-28s %s\n' "Connected for:" "$(human_duration "${connected_for_seconds}")"
                    else
                        printf '%-28s %s\n' "Connected for:" "Cannot be determined from available logs"
                    fi
                else
                    printf '%-28s %s\n' "Connected for:" "Cannot be determined from available logs"
                fi
                pause
                ;;
            3)
                echo
                section "RECENT STRONGSWAN LOGS"
                journalctl -u strongswan -n 30 --no-pager |
                    sed \
                        -e '/agent plugin requires CAP_SETUID\/CAP_SETGID capability/d' \
                        -e "/plugin 'agent': failed to load - agent_plugin_create returned NULL/d"
                pause
                ;;
            [bB]|0)
                return
                ;;
            [eE])
                clear_screen
                echo "Bye."
                exit 0
                ;;
            *)
                error "Invalid selection."
                sleep 1
                ;;
        esac
    done
}

# ============================================================================== 
# Export / Debian peer bundles
# ============================================================================== 

safe_export_component() {
    local value="$1"
    value="${value// /-}"
    value="$(printf '%s' "${value}" | tr -cd 'A-Za-z0-9._-')"
    [[ -n "${value}" ]] || value="tunnel"
    printf '%s' "${value}"
}

export_tunnel_backup() {
    banner
    section "EXPORT TUNNEL BACKUP"

    echo "Creates a portable backup of one S2S Manager tunnel."
    echo
    echo "The backup contains:"
    echo "  • manager tunnel definition"
    echo "  • configured remote networks"
    echo "  • stored PSK (if present)"
    echo
    echo "It does NOT contain active systemd/VTI/strongSwan runtime files."
    echo "To restore it later, use 'Tunnel backup / restore' -> 'Restore tunnel backup'."
    echo "A restored tunnel is returned to DEFINED state and can then be installed normally."
    echo
    warn "Backup files may contain the PSK. Store and transfer them securely."
    echo
    select_tunnel || return

    local name="${SELECTED_TUNNEL}"
    load_tunnel "${name}" || return
    local stamp base archive tmpdir
    stamp="$(date +%Y%m%d-%H%M%S)"
    base="$(safe_export_component "${DISPLAY_NAME}")-${stamp}"
    archive="${EXPORT_DIR}/${base}.s2s-backup.tar.gz"
    tmpdir="$(mktemp -d)"

    mkdir -p "${tmpdir}/tunnel"
    cp -a "$(tunnel_config_file "${name}")" "${tmpdir}/tunnel/"
    [[ -f "$(tunnel_route_file "${name}")" ]] && cp -a "$(tunnel_route_file "${name}")" "${tmpdir}/tunnel/"
    [[ -f "$(tunnel_secret_file "${name}")" ]] && cp -a "$(tunnel_secret_file "${name}")" "${tmpdir}/tunnel/"
    cat > "${tmpdir}/BACKUP-INFO.txt" <<EOF
S2S Manager tunnel backup
Manager version: ${VERSION}
Created: $(date -Is)
Display name: ${DISPLAY_NAME}
Internal name: ${NAME}
Contains PSK: $([[ -f "$(tunnel_secret_file "${name}")" ]] && echo yes || echo no)
EOF
    tar -C "${tmpdir}" -czf "${archive}" .
    chmod 600 "${archive}"
    rm -rf "${tmpdir}"

    ok "Tunnel backup created."
    printf '%-28s %s\n' "File:" "${archive}"
    warn "This backup contains sensitive tunnel data and may contain the PSK."
    pause
}

resolve_tunnel_peer_ipv4() {
    local mode="$1" address="$2"
    case "${mode}" in
        static)
            valid_ipv4 "${address}" || return 1
            printf '%s' "${address}"
            ;;
        dns)
            PEER_RESOLVED_IP=""
            PEER_RESOLVE_MULTIPLE=""
            resolve_peer_hostname "${address}" >/dev/null 2>&1 || return 1
            printf '%s' "${PEER_RESOLVED_IP}"
            ;;
        *) return 1 ;;
    esac
}


list_tunnel_backups() {
    find "${EXPORT_DIR}" -maxdepth 1 -type f -name '*.s2s-backup.tar.gz' -printf '%p\n' 2>/dev/null | sort
}

select_tunnel_backup() {
    local -a backups=()
    local f choice i

    while IFS= read -r f; do
        [[ -n "${f}" ]] && backups+=("${f}")
    done < <(list_tunnel_backups)

    if (( ${#backups[@]} == 0 )); then
        warn "No tunnel backup files found in ${EXPORT_DIR}."
        echo
        info "Create one first with 'Create tunnel backup', or choose a custom path."
        echo
        echo "  [P] Enter another backup path"
        echo "  [B] Back"
        echo "  [E] Exit"
        echo
        read -r -p "Selection: " choice
        case "${choice}" in
            p|P)
                read -r -p "Backup file: " SELECTED_BACKUP
                [[ -n "${SELECTED_BACKUP}" ]] || return 1
                ;;
            e|E) clear_screen; echo "Bye."; exit 0 ;;
            *) return 1 ;;
        esac
        return 0
    fi

    echo
    for i in "${!backups[@]}"; do
        printf '  [%d] %s\n' "$((i+1))" "$(basename "${backups[$i]}")"
    done
    echo
    echo "  [P] Enter another backup path"
    echo "  [B] Back"
    echo "  [E] Exit"
    echo
    read -r -p "Selection: " choice

    case "${choice}" in
        p|P)
            read -r -p "Backup file: " SELECTED_BACKUP
            [[ -n "${SELECTED_BACKUP}" ]] || return 1
            return 0
            ;;
        b|B|0|"") return 1 ;;
        e|E) clear_screen; echo "Bye."; exit 0 ;;
    esac

    [[ "${choice}" =~ ^[0-9]+$ ]] || return 1
    (( choice >= 1 && choice <= ${#backups[@]} )) || return 1
    SELECTED_BACKUP="${backups[$((choice-1))]}"
}

restore_tunnel_backup() {
    banner
    section "RESTORE TUNNEL BACKUP"

    echo "Restores a tunnel backup previously created by this S2S Manager."
    echo
    echo "Restore brings back:"
    echo "  • tunnel definition"
    echo "  • remote networks"
    echo "  • stored PSK (if included in the backup)"
    echo
    echo "The restored tunnel is always set to DEFINED."
    echo "No strongSwan file, VTI interface or systemd service is installed automatically."
    echo "After restore, use 'Install tunnel on Debian' when you are ready."
    echo
    echo "If the internal name or display name already exists, restore stops without changing anything."
    echo "No automatic -2 suffix is added and no existing tunnel is overwritten."
    echo

    select_tunnel_backup || return
    local archive="${SELECTED_BACKUP}"

    [[ -f "${archive}" ]] || {
        error "Backup file not found: ${archive}"
        pause
        return
    }

    command_available tar || {
        error "tar is required to restore a tunnel backup."
        pause
        return
    }

    local tmpdir
    tmpdir="$(mktemp -d)"
    chmod 700 "${tmpdir}"

    # Reject dangerous archive paths before extracting.
    local entry unsafe=0
    while IFS= read -r entry; do
        [[ -z "${entry}" ]] && continue
        case "${entry}" in
            /*|../*|*/../*|*/..)
                unsafe=1
                break
                ;;
        esac
    done < <(tar -tzf "${archive}" 2>/dev/null || true)

    if (( unsafe == 1 )); then
        rm -rf "${tmpdir}"
        validation_error_block \
            "UNSAFE BACKUP ARCHIVE" \
            "The backup contains an absolute or parent-directory path." \
            "No files were restored."
        pause
        return
    fi

    # Reject archive member types other than regular files/directories before extraction.
    # This also blocks symbolic links, hard links, devices, FIFOs and sockets.
    local tar_verbose tar_line tar_type
    if ! tar_verbose="$(tar -tvzf "${archive}" 2>/dev/null)"; then
        rm -rf "${tmpdir}"
        error "Could not read the tunnel backup archive."
        error "Tunnel backup was NOT restored."
        pause
        return
    fi

    [[ -n "${tar_verbose}" ]] || {
        rm -rf "${tmpdir}"
        error "Tunnel backup archive is empty."
        error "Tunnel backup was NOT restored."
        pause
        return
    }

    while IFS= read -r tar_line; do
        [[ -n "${tar_line}" ]] || continue
        tar_type="${tar_line:0:1}"
        if [[ "${tar_type}" != "-" && "${tar_type}" != "d" ]]; then
            rm -rf "${tmpdir}"
            validation_error_block \
                "UNSAFE BACKUP ARCHIVE" \
                "Only regular files and directories are allowed in a tunnel backup." \
                "Links, devices and other special archive members are rejected." \
                "No files were restored."
            error "Tunnel backup was NOT restored."
            pause
            return
        fi
    done <<< "${tar_verbose}"

    if ! tar -xzf "${archive}" -C "${tmpdir}" --no-same-owner --no-same-permissions \
        >/tmp/s2s-manager-restore-tar.log 2>&1; then
        rm -rf "${tmpdir}"
        error "Could not extract the tunnel backup."
        cat /tmp/s2s-manager-restore-tar.log 2>/dev/null || true
        pause
        return
    fi

    # Only the exact manager backup structure is allowed after extraction.
    # Reject symlinks, hard/special files, extra directories and unexpected files.
    local tree_entry rel type tree_invalid=0
    while IFS='|' read -r rel type; do
        [[ -n "${rel}" ]] || continue
        case "${rel}|${type}" in
            "tunnel|d"|"BACKUP-INFO.txt|f")
                ;;
            tunnel/*.conf'|f'|tunnel/*.routes'|f'|tunnel/*.psk'|f')
                local base_name="${rel#tunnel/}"
                base_name="${base_name%.*}"
                valid_tunnel_name "${base_name}" || { tree_invalid=1; break; }
                ;;
            *)
                tree_invalid=1
                break
                ;;
        esac
    done < <(find "${tmpdir}" -mindepth 1 -printf '%P|%y\n' 2>/dev/null)

    if (( tree_invalid == 1 )); then
        rm -rf "${tmpdir}"
        validation_error_block \
            "UNSAFE / INVALID BACKUP ARCHIVE" \
            "The backup contains an unexpected path or file type." \
            "Only BACKUP-INFO.txt and regular .conf/.routes/.psk files under tunnel/ are allowed." \
            "No files were restored."
        error "Tunnel backup was NOT restored."
        pause
        return
    fi

    if [[ ! -f "${tmpdir}/BACKUP-INFO.txt" ]]; then
        rm -rf "${tmpdir}"
        validation_error_block \
            "INVALID BACKUP ARCHIVE" \
            "BACKUP-INFO.txt is missing." \
            "This does not look like a complete S2S Manager tunnel backup." \
            "No files were restored."
        error "Tunnel backup was NOT restored."
        pause
        return
    fi

    local -a confs=()
    mapfile -t confs < <(find "${tmpdir}/tunnel" -maxdepth 1 -type f -name '*.conf' -print 2>/dev/null)
    if (( ${#confs[@]} != 1 )); then
        rm -rf "${tmpdir}"
        error "Backup must contain exactly one tunnel definition."
        pause
        return
    fi

    local conf="${confs[0]}"
    local internal
    internal="$(basename "${conf}" .conf)"

    local tunnel_member member_base
    while IFS= read -r tunnel_member; do
        [[ -n "${tunnel_member}" ]] || continue
        member_base="$(basename "${tunnel_member}")"
        case "${member_base}" in
            "${internal}.conf"|"${internal}.routes"|"${internal}.psk")
                ;;
            *)
                rm -rf "${tmpdir}"
                validation_error_block \
                    "INVALID BACKUP ARCHIVE" \
                    "Unexpected tunnel file: ${member_base}" \
                    "All tunnel files in one backup must belong to the same internal tunnel name." \
                    "No files were restored."
                error "Tunnel backup was NOT restored."
                pause
                return
                ;;
        esac
    done < <(find "${tmpdir}/tunnel" -maxdepth 1 -type f -print 2>/dev/null)

    # Parse the external backup definition as data only. Never source it as shell code.
    if ! read_external_tunnel_config "${conf}"; then
        rm -rf "${tmpdir}"
        validation_error_block \
            "INVALID BACKUP CONFIGURATION" \
            "The tunnel definition contains an unknown, duplicate or invalid field." \
            "No shell code from backup files is executed." \
            "No files were restored."
        error "Tunnel backup was NOT restored."
        pause
        return
    fi

    NAME="${EXT_NAME}"
    DISPLAY_NAME="${EXT_DISPLAY_NAME}"
    PUBLIC_IP="${EXT_PUBLIC_IP}"
    AUTH_ID="${EXT_AUTH_ID}"
    VTI_INTERFACE="${EXT_VTI_INTERFACE}"
    VTI_KEY="${EXT_VTI_KEY}"
    VTI_NETWORK="${EXT_VTI_NETWORK}"
    DEBIAN_VTI_IP="${EXT_DEBIAN_VTI_IP}"
    UNIFI_VTI_IP="${EXT_UNIFI_VTI_IP}"
    PEER_MODE="${EXT_PEER_MODE}"
    PEER_ADDRESS="${EXT_PEER_ADDRESS}"
    PEER_TYPE="${EXT_PEER_TYPE}"
    INSTALLED="0"

    if [[ "${NAME}" != "${internal}" ]]; then
        rm -rf "${tmpdir}"
        validation_error_block \
            "INVALID BACKUP" \
            "Internal tunnel name does not match the backup filename." \
            "Config name: ${NAME}" \
            "File name:   ${internal}"
        pause
        return
    fi

    if tunnel_exists "${NAME}" || internal_name_artifacts_exist "${NAME}"; then
        rm -rf "${tmpdir}"
        validation_error_block \
            "TUNNEL ALREADY EXISTS" \
            "Internal name: ${NAME}" \
            "Restore stops here without changing anything." \
            "No automatic -2 suffix is added and the existing tunnel is not overwritten."
        error "Tunnel backup was NOT restored."
        pause
        return
    fi

    if display_name_in_use "${DISPLAY_NAME}"; then
        rm -rf "${tmpdir}"
        validation_error_block \
            "DISPLAY NAME ALREADY EXISTS" \
            "Display name: ${DISPLAY_NAME}" \
            "Restore stops here without changing anything." \
            "No automatic -2 suffix is added and the existing display name is not changed."
        error "Tunnel backup was NOT restored."
        pause
        return
    fi

    if check_network_conflict "${VTI_NETWORK}"; then
        show_network_conflict "${VTI_NETWORK}"
        rm -rf "${tmpdir}"
        pause
        return
    fi

    local detected_public
    detected_public="$(detect_public_ipv4)"
    if [[ -n "${detected_public}" && "${PUBLIC_IP}" != "${detected_public}" ]]; then
        validation_error_block \
            "LOCAL PUBLIC IP MISMATCH" \
            "Backup local Debian IP: ${PUBLIC_IP}" \
            "Detected server IP:     ${detected_public}" \
            "" \
            "This backup belongs to a different local IPsec endpoint." \
            "No files were restored."
        rm -rf "${tmpdir}"
        pause
        return
    fi

    # Keep original VTI allocation if still free; otherwise allocate a new one.
    if interface_in_system_use "${VTI_INTERFACE}" || vti_key_in_system_use "${VTI_KEY}"; then
        local idx
        idx="$(next_interface_index)"
        VTI_INTERFACE="ipsec${idx}"
        VTI_KEY=$((DEFAULT_VTI_KEY + idx))
        info "Original VTI resources are already in use; new resources were allocated."
    fi

    local route_src="${tmpdir}/tunnel/${NAME}.routes"
    local psk_src="${tmpdir}/tunnel/${NAME}.psk"
    local psk_present="no"
    [[ -f "${psk_src}" ]] && psk_present="yes"

    section "RESTORE PREVIEW"
    printf '%-28s %s\n' "Display name:" "${DISPLAY_NAME}"
    printf '%-28s %s\n' "Internal name:" "${NAME}"
    printf '%-28s %s\n' "Peer type:" "$(peer_type_label "${PEER_TYPE}")"
    printf '%-28s %s\n' "Local Debian public IP:" "${PUBLIC_IP}"
    printf '%-28s %s\n' "VTI interface:" "${VTI_INTERFACE}"
    printf '%-28s %s\n' "VTI key / mark:" "${VTI_KEY}"
    printf '%-28s %s\n' "Tunnel network:" "${VTI_NETWORK}"
    printf '%-28s %s\n' "PSK included:" "${psk_present}"
    echo
    echo "The tunnel will be restored as DEFINED and will not be installed yet."
    echo

    confirm_yes_no "Restore this tunnel backup?" "N" || {
        rm -rf "${tmpdir}"
        return
    }

    save_tunnel \
        "${NAME}" "${PUBLIC_IP}" "${AUTH_ID}" "${VTI_INTERFACE}" "${VTI_KEY}" \
        "${VTI_NETWORK}" "${DEBIAN_VTI_IP}" "${UNIFI_VTI_IP}" "0" \
        "${PEER_MODE}" "${PEER_ADDRESS}" "${DISPLAY_NAME}" "${PEER_TYPE}"

    if [[ -f "${route_src}" ]]; then
        cp -a "${route_src}" "$(tunnel_route_file "${NAME}")"
        chmod 600 "$(tunnel_route_file "${NAME}")"
    else
        write_routes "${NAME}"
    fi

    if [[ -f "${psk_src}" ]]; then
        cp -a "${psk_src}" "$(tunnel_secret_file "${NAME}")"
        chmod 600 "$(tunnel_secret_file "${NAME}")"
    fi

    rm -rf "${tmpdir}"

    echo
    ok "Tunnel backup restored successfully."
    printf '%-28s %s\n' "State:" "DEFINED / MANAGED"
    if [[ "${psk_present}" == "yes" ]]; then
        ok "Stored PSK restored."
    else
        warn "This backup did not contain a PSK. Installation will require a valid PSK."
    fi
    info "Use 'Install tunnel on Debian' to install the restored tunnel."
    pause
}

tunnel_backup_menu() {
    while :; do
        banner
        section "TUNNEL BACKUP / RESTORE"

        echo "Backups are for saving and restoring an S2S Manager tunnel on the same"
        echo "local IPsec endpoint. They contain the manager definition, remote networks"
        echo "and the stored PSK (if present), but not active Debian system files."
        echo
        echo "  [1] Create tunnel backup"
        echo "      Save a portable .s2s-backup.tar.gz file."
        echo
        echo "  [2] Restore tunnel backup"
        echo "      Restore a backup to DEFINED state; install it afterwards if needed."
        echo
        echo "  [B] Back"
        echo "  [E] Exit"
        echo

        local choice
        read -r -p "Selection: " choice
        case "${choice}" in
            1) export_tunnel_backup; return ;;
            2) restore_tunnel_backup; return ;;
            b|B|0|"") return ;;
            e|E) clear_screen; echo "Bye."; exit 0 ;;
            *) error "Invalid selection."; sleep 1 ;;
        esac
    done
}

create_debian_peer_bundle() {
    banner
    section "CREATE DEBIAN PEER BUNDLE"

    echo "Creates the mirrored configuration for the other Debian / strongSwan server."
    echo "The bundle contains the matching endpoint/VTI settings and the same PSK."
    echo "Create it on one side, then transfer and import it on the peer server."
    echo
    select_tunnel || return

    local name="${SELECTED_TUNNEL}"
    load_tunnel "${name}" || return
    if [[ "${MANAGEMENT}" == "IMPORTED" ]]; then
        imported_readonly_notice "${name}"
        pause
        return
    fi
    if [[ "${PEER_MODE}" == "dynamic" ]]; then
        error "A Debian peer bundle requires a fixed peer endpoint."
        echo "Use Static IPv4 or Hostname / Dynamic DNS for Debian-to-Debian tunnels."
        pause
        return
    fi

    local peer_public_ip
    peer_public_ip="$(resolve_tunnel_peer_ipv4 "${PEER_MODE}" "${PEER_ADDRESS}" 2>/dev/null || true)"
    if [[ -z "${peer_public_ip}" ]]; then
        error "The peer endpoint could not be resolved to exactly one IPv4 address."
        pause
        return
    fi

    local psk
    psk="$(read_psk "${name}" 2>/dev/null || true)"
    if [[ -z "${psk}" ]]; then
        error "Stored PSK not found."
        pause
        return
    fi

    if [[ "${AUTH_ID}" != "${peer_public_ip}" ]]; then
        validation_error_block \
            "DEBIAN PEER AUTHENTICATION ID MISMATCH" \
            "Current Authentication ID: ${AUTH_ID}" \
            "Peer public IPv4:          ${peer_public_ip}" \
            "" \
            "For a mirrored Debian peer, the current tunnel must expect the" \
            "peer Debian server's public IPv4 as its remote Authentication ID." \
            "Create/correct the tunnel with Authentication ID ${peer_public_ip}."
        pause
        return
    fi

    local suggested_display peer_display bundle stamp
    suggested_display="${DISPLAY_NAME} - Peer"
    echo "The peer bundle creates the mirrored tunnel on the other Debian server."
    echo "It contains the PSK and must be treated as sensitive."
    echo
    printf 'Peer display name [%s]: ' "${suggested_display}"
    read -r peer_display
    [[ -n "${peer_display}" ]] || peer_display="${suggested_display}"
    if ! valid_display_name "${peer_display}"; then
        error "Invalid display name."
        pause
        return
    fi

    stamp="$(date +%Y%m%d-%H%M%S)"
    bundle="${EXPORT_DIR}/$(safe_export_component "${DISPLAY_NAME}")-${stamp}.s2s-peer"

    cat > "${bundle}" <<EOF
S2S_PEER_BUNDLE_VERSION=1
CREATED_BY_VERSION=$(printf '%q' "${VERSION}")
CREATED_AT=$(printf '%q' "$(date -Is)")
SOURCE_DISPLAY_NAME=$(printf '%q' "${DISPLAY_NAME}")
PEER_DISPLAY_NAME=$(printf '%q' "${peer_display}")
PUBLIC_IP=$(printf '%q' "${peer_public_ip}")
REMOTE_PUBLIC_IP=$(printf '%q' "${PUBLIC_IP}")
AUTH_ID=$(printf '%q' "${PUBLIC_IP}")
VTI_NETWORK=$(printf '%q' "${VTI_NETWORK}")
LOCAL_VTI_IP=$(printf '%q' "${UNIFI_VTI_IP}")
REMOTE_VTI_IP=$(printf '%q' "${DEBIAN_VTI_IP}")
PSK=$(printf '%q' "${psk}")
EOF
    chmod 600 "${bundle}"

    echo
    ok "Debian peer bundle created."
    printf '%-28s %s\n' "File:" "${bundle}"
    printf '%-28s %s\n' "Peer public IP:" "${peer_public_ip}"
    printf '%-28s %s\n' "Peer VTI IP:" "${UNIFI_VTI_IP}"
    printf '%-28s %s\n' "Remote VTI IP:" "${DEBIAN_VTI_IP}"
    echo
    info "You can transfer this bundle later with 'Transfer Debian peer bundle'."
    echo
    if confirm_yes_no "Transfer it now via SCP?" "N"; then
        transfer_debian_peer_bundle "${bundle}"
        return
    fi
    pause
}

list_peer_bundles() {
    find "${EXPORT_DIR}" -maxdepth 1 -type f -name '*.s2s-peer' -printf '%p\n' 2>/dev/null | sort
}

select_peer_bundle() {
    local -a bundles=()
    local f choice i
    while read -r f; do [[ -n "${f}" ]] && bundles+=("${f}"); done < <(list_peer_bundles)
    if (( ${#bundles[@]} == 0 )); then
        warn "No Debian peer bundles found in ${EXPORT_DIR}."
        echo
        info "Create one first with 'Create Debian peer bundle'."
        echo "Nothing was transferred."
        pause
        return 1
    fi
    echo
    for i in "${!bundles[@]}"; do printf '  [%d] %s\n' "$((i+1))" "$(basename "${bundles[$i]}")"; done
    echo
    echo "B = Back    E = Exit"
    read -r -p "Selection: " choice
    case "${choice}" in
        b|B|0|"") return 1 ;;
        e|E) clear_screen; echo "Bye."; exit 0 ;;
    esac
    [[ "${choice}" =~ ^[0-9]+$ ]] || return 1
    (( choice >= 1 && choice <= ${#bundles[@]} )) || return 1
    SELECTED_BUNDLE="${bundles[$((choice-1))]}"
}

transfer_debian_peer_bundle() {
    local bundle="${1:-}"
    banner
    section "TRANSFER DEBIAN PEER BUNDLE VIA SCP"

    echo "Transfers an already created Debian peer bundle directly to the remote server via SCP."
    echo "The transfer is encrypted over SSH; your local computer is not used as an intermediate hop."
    echo
    echo "The remote import directory is created automatically if it does not already exist."
    echo "With normal password-based SSH you may be asked for the remote SSH password twice:"
    echo "  • first to check/create the remote import directory"
    echo "  • second for the actual SCP file transfer"
    echo "With SSH key authentication, no password prompt may be necessary."
    echo
    echo "On the remote server, import the transferred file with 'Import Debian peer bundle'."
    echo
    if [[ -z "${bundle}" ]]; then
        select_peer_bundle || return
        bundle="${SELECTED_BUNDLE}"
    fi
    command_available scp || { error "scp is not installed."; pause; return; }

    local host user port remote_dir target suggested_host="" raw_host

    # Peer bundles already contain the peer server's public IPv4 address. Use it
    # as the default SSH destination, but still allow a DNS hostname instead.
    if read_peer_bundle "${bundle}" >/dev/null 2>&1; then
        suggested_host="${PUBLIC_IP:-}"
    fi

    echo "Enter the remote SSH server as an IPv4 address or DNS hostname."
    echo "Examples: 94.130.110.232 or server.example.org"
    echo "Do not include http:// or https:// (it will be removed automatically)."
    echo

    while :; do
        if [[ -n "${suggested_host}" ]]; then
            read -r -p "Remote SSH server (hostname or IPv4) [${suggested_host}]: " raw_host
            [[ -n "${raw_host}" ]] || raw_host="${suggested_host}"
        else
            read -r -p "Remote SSH server (hostname or IPv4): " raw_host
        fi

        host="${raw_host#http://}"
        host="${host#https://}"
        host="${host%%/*}"
        host="${host%%:*}"

        if [[ -z "${host}" ]]; then
            error "Remote SSH server is required."
            continue
        fi

        if [[ "${host}" != "${raw_host}" ]]; then
            info "Using SSH server: ${host}"
        fi
        break
    done

    read -r -p "SSH user [root]: " user
    [[ -n "${user}" ]] || user="root"
    read -r -p "SSH port [22]: " port
    [[ -n "${port}" ]] || port="22"
    [[ "${port}" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )) || { error "Invalid SSH port."; pause; return; }
    read -r -p "Remote import directory [/root/s2s-manager-import]: " remote_dir
    [[ -n "${remote_dir}" ]] || remote_dir="/root/s2s-manager-import"

    echo
    printf '%-28s %s\n' "Bundle:" "${bundle}"
    printf '%-28s %s\n' "Destination:" "${user}@${host}:${remote_dir}/"
    echo
    warn "The bundle contains the tunnel PSK. SCP encrypts the transfer over SSH."
    confirm_yes_no "Transfer this bundle now?" "N" || return

    info "Checking / preparing remote import directory..."
    if ! ssh -p "${port}" "${user}@${host}" "mkdir -p -- $(printf '%q' "${remote_dir}") && chmod 700 -- $(printf '%q' "${remote_dir}")"; then
        error "Could not create or prepare the remote import directory."
        echo "The bundle was not transferred and remains available locally."
        pause
        return
    fi
    ok "Remote import directory is ready: ${remote_dir}"

    info "Transferring peer bundle via SCP..."
    if scp -P "${port}" -- "${bundle}" "${user}@${host}:${remote_dir}/"; then
        target="${remote_dir}/$(basename "${bundle}")"
        echo
        ok "Peer bundle transferred successfully."
        printf '%-28s %s\n' "Remote file:" "${target}"
        info "Run S2S Manager on the peer and choose 'Import Debian peer bundle'."
    else
        error "SCP transfer failed. The local bundle was kept unchanged."
    fi
    pause
}



import_debian_peer_bundle() {
    banner
    section "IMPORT DEBIAN PEER BUNDLE"

    echo "Imports a Debian peer bundle created on the other S2S Manager server."
    echo "It creates the mirrored local tunnel definition and stores the included PSK."
    echo "After the preview and conflict checks, the tunnel can be installed on this Debian server."
    echo

    local default_dir="/root/s2s-manager-import"
    local -a bundles=()
    local file="" f choice i

    mkdir -p "${default_dir}" 2>/dev/null || true
    while IFS= read -r f; do
        [[ -n "${f}" ]] && bundles+=("${f}")
    done < <(find "${default_dir}" -maxdepth 1 -type f -name '*.s2s-peer' -printf '%p\n' 2>/dev/null | sort)

    if (( ${#bundles[@]} > 0 )); then
        echo "Peer bundles found in ${default_dir}:"
        echo
        for i in "${!bundles[@]}"; do
            printf '  [%d] %s\n' "$((i+1))" "$(basename "${bundles[$i]}")"
        done
        echo
        echo "  [P] Enter another bundle path"
        echo "  [B] Back"
        echo "  [E] Exit"
        echo
        while :; do
            read -r -p "Selection: " choice
            case "${choice}" in
                [1-9]|[1-9][0-9]*)
                    if (( choice >= 1 && choice <= ${#bundles[@]} )); then
                        file="${bundles[$((choice-1))]}"
                        break
                    fi
                    error "Invalid selection."
                    ;;
                p|P)
                    read -r -p "Bundle file: " file
                    [[ -n "${file}" ]] || return
                    break
                    ;;
                b|B|0) return ;;
                e|E) clear_screen; echo "Bye."; exit 0 ;;
                *) error "Invalid selection." ;;
            esac
        done
    else
        echo "No peer bundles were found in ${default_dir}."
        echo
        echo "Enter another peer bundle path, or press ENTER to go back."
        read -r -p "Bundle file: " file
        [[ -n "${file}" ]] || return
    fi

    if ! read_peer_bundle "${file}"; then
        error "Invalid or unsupported Debian peer bundle."
        pause
        return
    fi

    # IMPORTANT:
    # Bundle fields use some of the same variable names as load_tunnel().
    # Conflict helpers call load_tunnel() internally, so snapshot every bundle
    # value into locals before running any validation.
    local bundle_source_display="${SOURCE_DISPLAY_NAME:-}"
    local bundle_peer_display="${PEER_DISPLAY_NAME:-${SOURCE_DISPLAY_NAME:-Debian-Peer}}"
    local bundle_public_ip="${PUBLIC_IP}"
    local bundle_remote_public_ip="${REMOTE_PUBLIC_IP}"
    local bundle_auth_id="${AUTH_ID}"
    local bundle_vti_network="${VTI_NETWORK}"
    local bundle_local_vti_ip="${LOCAL_VTI_IP}"
    local bundle_remote_vti_ip="${REMOTE_VTI_IP}"
    local bundle_psk="${PSK}"

    local normalized
    normalized="$(normalize_30_network "${bundle_vti_network}" 2>/dev/null || true)"
    if [[ -z "${normalized}" || "${normalized}" != "${bundle_vti_network}" ]]; then
        validation_error_block \
            "INVALID PEER BUNDLE" \
            "Tunnel network is not a valid /30 network base." \
            "Tunnel network: ${bundle_vti_network}"
        pause
        return
    fi

    # The two VTI addresses must be exactly the two usable hosts of the /30.
    calculate_30_addresses "${bundle_vti_network}"
    if ! {
        [[ "${bundle_local_vti_ip}" == "${CALC_DEBIAN}" && "${bundle_remote_vti_ip}" == "${CALC_UNIFI}" ]] ||
        [[ "${bundle_local_vti_ip}" == "${CALC_UNIFI}" && "${bundle_remote_vti_ip}" == "${CALC_DEBIAN}" ]]
    }; then
        validation_error_block \
            "INVALID PEER BUNDLE" \
            "The VTI addresses do not belong to the declared tunnel /30." \
            "Tunnel network: ${bundle_vti_network}" \
            "Usable hosts:   ${CALC_DEBIAN}, ${CALC_UNIFI}" \
            "Local VTI IP:   ${bundle_local_vti_ip}" \
            "Remote VTI IP:  ${bundle_remote_vti_ip}"
        pause
        return
    fi

    # Debian peer bundles use the remote server's public IPv4 as IKE ID.
    if [[ "${bundle_auth_id}" != "${bundle_remote_public_ip}" ]]; then
        validation_error_block \
            "INVALID PEER BUNDLE" \
            "Authentication ID does not match the remote Debian public IPv4." \
            "Authentication ID: ${bundle_auth_id}" \
            "Remote public IP:  ${bundle_remote_public_ip}"
        pause
        return
    fi

    local detected_public
    detected_public="$(detect_public_ipv4)"
    if [[ -n "${detected_public}" && "${bundle_public_ip}" != "${detected_public}" ]]; then
        validation_error_block \
            "PEER BUNDLE FOR ANOTHER SERVER" \
            "Bundle local public IP:    ${bundle_public_ip}" \
            "Detected server public IP: ${detected_public}" \
            "" \
            "Import this bundle on the Debian server it was created for."
        pause
        return
    fi

    section "LOCAL CONFLICT VALIDATION"
    local validation_failed=0

    if check_network_conflict "${bundle_vti_network}"; then
        show_network_conflict "${bundle_vti_network}"
        validation_failed=1
    else
        ok "Tunnel network is available on this Debian server: ${bundle_vti_network}"
    fi

    if find_specific_vti_conflict "${bundle_public_ip}" "${bundle_remote_public_ip}" ""; then
        validation_error_block \
            "VTI ENDPOINT CONFLICT" \
            "Local public IP:   ${bundle_public_ip}" \
            "Remote public IP:  ${bundle_remote_public_ip}" \
            "Existing VTI:      ${VTI_TOPOLOGY_CONFLICT_INTERFACE}" \
            "" \
            "This local/remote endpoint pair is already used by another VTI."
        validation_failed=1
    else
        ok "VTI endpoint pair is available: ${bundle_public_ip} <-> ${bundle_remote_public_ip}"
    fi

    if (( validation_failed != 0 )); then
        echo
        error "Peer bundle import stopped before any manager files or PSK were written."
        pause
        return
    fi

    local peer_display="${bundle_peer_display}"
    if display_name_in_use "${peer_display}"; then
        warn "Display name '${peer_display}' already exists."
        prompt_display_name "${peer_display}"
        peer_display="${PROMPT_RESULT}"
    fi

    local internal idx interface key
    internal="$(next_internal_name_for_display "${peer_display}")"
    idx="$(next_interface_index)"
    interface="ipsec${idx}"
    key=$((DEFAULT_VTI_KEY + idx))

    # next_interface_index() checks manager state and live Debian VTI resources.
    if interface_in_system_use "${interface}" || vti_key_in_system_use "${key}"; then
        validation_error_block \
            "VTI ALLOCATION CONFLICT" \
            "Requested interface: ${interface}" \
            "Requested key/mark:  ${key}" \
            "" \
            "The automatically selected VTI resources became unavailable."
        pause
        return
    fi

    ok "VTI interface allocation: ${interface} (free)"
    ok "VTI key / mark allocation: ${key} (free)"

    echo
    section "PEER IMPORT PREVIEW"
    printf '%-28s %s\n' "Display name:" "${peer_display}"
    printf '%-28s %s\n' "Internal name:" "${internal}"
    printf '%-28s %s\n' "Local public IP:" "${bundle_public_ip}"
    printf '%-28s %s\n' "Remote public IP:" "${bundle_remote_public_ip}"
    printf '%-28s %s\n' "Authentication ID:" "${bundle_auth_id}"
    printf '%-28s %s\n' "VTI interface:" "${interface}"
    printf '%-28s %s\n' "VTI key / mark:" "${key}"
    printf '%-28s %s\n' "Tunnel network:" "${bundle_vti_network}"
    printf '%-28s %s\n' "Local VTI IP:" "${bundle_local_vti_ip}"
    printf '%-28s %s\n' "Remote VTI IP:" "${bundle_remote_vti_ip}"
    echo
    warn "The bundle contains and will store the shared PSK."
    confirm_yes_no "Import this Debian peer tunnel definition?" "N" || return

    save_tunnel "${internal}" "${bundle_public_ip}" "${bundle_auth_id}" "${interface}" "${key}" \
        "${bundle_vti_network}" "${bundle_local_vti_ip}" "${bundle_remote_vti_ip}" \
        "0" "static" "${bundle_remote_public_ip}" "${peer_display}" "debian"
    write_routes "${internal}"
    save_psk "${internal}" "${bundle_psk}"

    ok "Debian peer tunnel definition imported."
    info "The tunnel is defined but not installed yet."
    echo
    if confirm_yes_no "Install this tunnel on Debian now?" "N"; then
        if ensure_ipsec_ready_for_action; then
            install_tunnel_system_config "${internal}"
        else
            info "The imported definition remains saved and can be installed later."
            pause
        fi
    else
        info "You can install it later with 'Install tunnel on Debian'."
        if confirm_yes_no "Delete the imported bundle file now?" "N"; then
            rm -f -- "${file}"
            ok "Imported bundle file deleted."
        fi
        pause
    fi
}

# ==============================================================================
# Menus
# ==============================================================================

ensure_ipsec_ready_for_action() {
    preflight_ready && return 0

    while :; do
        banner
        section "IPSEC COMPONENTS REQUIRED"
        echo "The selected operation requires a prepared strongSwan/IPsec environment."
        echo "It is not required for Cron, UFW, IPTABLES, WireGuard or general system information."
        echo
        echo "Nothing is installed or changed unless you explicitly select setup below"
        echo "and confirm its detailed preview."
        echo
        echo "  [1] Install / repair IPsec prerequisites"
        echo "  [2] Show detailed IPsec pre-flight check"
        echo "  [B] Back to main menu"
        echo "  [E] Exit"
        echo

        local choice
        read -r -p "Selection: " choice

        case "${choice}" in
            1)
                install_or_repair_prerequisites
                if preflight_ready; then
                    ok "IPsec components are ready. Continuing the selected operation."
                    sleep 1
                    return 0
                fi
                ;;
            2)
                show_preflight || true
                pause
                ;;
            b|B|0|"") return 1 ;;
            e|E) clear_screen; echo "Bye."; exit 0 ;;
            *) error "Invalid selection."; sleep 1 ;;
        esac
    done
}

run_ipsec_action() {
    local action="$1"
    ensure_ipsec_ready_for_action || return 0
    "${action}"
}

# ==============================================================================
# Read-only access path check
# ==============================================================================

ACCESS_CHECK_OK=0
ACCESS_CHECK_WARN=0
ACCESS_CHECK_FAIL=0

access_check_ok() {
    ACCESS_CHECK_OK=$((ACCESS_CHECK_OK + 1))
    ok "$*"
}

access_check_warn() {
    ACCESS_CHECK_WARN=$((ACCESS_CHECK_WARN + 1))
    warn "$*"
}

access_check_fail() {
    ACCESS_CHECK_FAIL=$((ACCESS_CHECK_FAIL + 1))
    error "$*"
}

access_check_first_ip() {
    local value="$1" network prefix candidate
    if valid_ipv4 "${value}"; then
        printf '%s' "${value}"
        return 0
    fi
    valid_cidr "${value}" || return 1
    network="$(cidr_network_int "${value}")"
    prefix="${value##*/}"
    candidate="${network}"
    (( prefix < 31 )) && candidate=$((network + 1))
    int_to_ipv4 "${candidate}"
}

access_check_cidr_contains() {
    local outer="$1" inner="$2" outer_net outer_end inner_net inner_end outer_prefix inner_prefix
    valid_ipv4 "${outer}" && outer="${outer}/32"
    valid_ipv4 "${inner}" && inner="${inner}/32"
    valid_cidr "${outer}" && valid_cidr "${inner}" || return 1
    outer_prefix="${outer##*/}"
    inner_prefix="${inner##*/}"
    (( outer_prefix <= inner_prefix )) || return 1
    outer_net="$(cidr_network_int "${outer}")"
    inner_net="$(cidr_network_int "${inner}")"
    outer_end=$((outer_net + (1 << (32 - outer_prefix)) - 1))
    inner_end=$((inner_net + (1 << (32 - inner_prefix)) - 1))
    (( outer_net <= inner_net && outer_end >= inner_end ))
}

access_check_ufw_allows_local_service() {
    local port="$1" proto="$2" source="$3" line rule_source added
    ufw_installed || return 1
    added="$(ufw show added 2>/dev/null || true)"
    while IFS= read -r line; do
        if grep -Eq "^ufw[[:space:]]+allow([[:space:]]+in)?[[:space:]]+${port}/${proto}([[:space:]]|$)" <<< "${line}"; then
            return 0
        fi
        if [[ "${line}" =~ allow[[:space:]]+from[[:space:]]+([^[:space:]]+)[[:space:]]+to[[:space:]]+any[[:space:]]+port[[:space:]]+${port}[[:space:]]+proto[[:space:]]+${proto}([[:space:]]|$) ]]; then
            rule_source="${BASH_REMATCH[1]}"
            access_check_cidr_contains "${rule_source}" "${source}" && return 0
        fi
    done <<< "${added}"
    return 1
}

access_check_select_wireguard_client() {
    local -a ids=()
    local id choice i=0

    while read -r id; do
        [[ -n "${id}" ]] && ids+=("${id}")
    done < <(list_wireguard_client_ids)
    (( ${#ids[@]} > 0 )) || { error "No WireGuard clients are configured in the manager."; return 1; }

    echo
    echo "Configured WireGuard clients:"
    for id in "${ids[@]}"; do
        load_wireguard_client "${id}" || continue
        i=$((i + 1))
        printf '  [%d] %-24s %s\n' "${i}" "${WG_CLIENT_NAME}" "${WG_CLIENT_IP}"
    done
    echo "  [B] Back"
    echo "  [E] Exit"
    echo
    read -r -p "Client: " choice
    case "${choice}" in
        b|B|0|"") return 1 ;;
        e|E) clear_screen; echo "Bye."; exit 0 ;;
    esac
    [[ "${choice}" =~ ^[0-9]+$ ]] || { error "Enter a listed client number."; return 1; }
    (( choice >= 1 && choice <= ${#ids[@]} )) || { error "Client number does not exist."; return 1; }
    load_wireguard_client "${ids[$((choice-1))]}" || return 1
    ACCESS_SOURCE_LABEL="WireGuard client ${WG_CLIENT_NAME}"
    ACCESS_SOURCE_VALUE="${WG_CLIENT_IP}/32"
    ACCESS_SOURCE_IP="${WG_CLIENT_IP}"
    ACCESS_INGRESS_IF="${WG_INTERFACE:-wg0}"
    ACCESS_WG_CLIENT_ID="${ids[$((choice-1))]}"
}

access_check_suggest_interface() {
    local source_ip="$1" route
    route="$(ip -4 route get "${source_ip}" 2>/dev/null || true)"
    awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' <<< "${route}"
}

access_check_select_interface() {
    local suggested="$1" choice iface addresses i=0
    local -a interfaces=()

    while read -r iface; do
        [[ -n "${iface}" ]] && interfaces+=("${iface}")
    done < <(ip -o link show 2>/dev/null | awk -F': ' '{name=$2; sub(/@.*/, "", name); print name}')
    (( ${#interfaces[@]} > 0 )) || { error "No Linux network interfaces could be listed."; return 1; }

    echo
    echo "The ingress interface is required for an accurate forwarded-packet route"
    echo "simulation and for interface-specific firewall rules. Choose the interface"
    echo "on which traffic from ${ACCESS_SOURCE_VALUE} enters this server."
    echo
    echo "Available interfaces:"
    for iface in "${interfaces[@]}"; do
        i=$((i + 1))
        addresses="$(ip -o -4 addr show dev "${iface}" 2>/dev/null | awk '{print $4}' | paste -sd ',' -)"
        [[ -n "${addresses}" ]] || addresses="no IPv4 address"
        if [[ "${iface}" == "${suggested}" ]]; then
            printf '  [%d] %-18s %-24s  [suggested]\n' "${i}" "${iface}" "${addresses}"
        else
            printf '  [%d] %-18s %s\n' "${i}" "${iface}" "${addresses}"
        fi
    done
    [[ -n "${suggested}" ]] && echo "  [A] Use suggested interface: ${suggested}"
    echo "  [B] Back"
    echo "  [E] Exit"
    echo
    read -r -p "Ingress interface: " choice
    case "${choice}" in
        a|A)
            [[ -n "${suggested}" ]] || { error "No interface suggestion is available."; return 1; }
            ACCESS_INGRESS_IF="${suggested}"
            ;;
        b|B|0|"") return 1 ;;
        e|E) clear_screen; echo "Bye."; exit 0 ;;
        *)
            [[ "${choice}" =~ ^[0-9]+$ ]] || { error "Enter a listed interface number."; return 1; }
            (( choice >= 1 && choice <= ${#interfaces[@]} )) || { error "Interface number does not exist."; return 1; }
            ACCESS_INGRESS_IF="${interfaces[$((choice-1))]}"
            ;;
    esac
}

access_check_collect_source() {
    local choice value suggested ssh_peer
    ACCESS_WG_CLIENT_ID=""

    banner
    section "ACCESS CHECK - SOURCE"
    cat <<'EOF'
Select where the connection would originate. This check does not send traffic
as that remote device and does not modify firewall or routing configuration.

  [1] Configured WireGuard client
  [2] Custom source IPv4/CIDR and ingress interface
  [B] Back
  [E] Exit
EOF
    ssh_peer="$(awk '{print $1}' <<< "${SSH_CONNECTION:-}")"
    if valid_ipv4 "${ssh_peer}"; then
        echo
        info "Current SSH peer visible to this server: ${ssh_peer}"
        echo "This public/NAT address is informational and is not treated as a forwarded network source."
    fi
    echo
    read -r -p "Source: " choice
    case "${choice}" in
        1)
            wireguard_server_known || { error "No WireGuard server is known to the manager."; pause; return 1; }
            load_wireguard_server || { error "WireGuard server state could not be loaded."; pause; return 1; }
            access_check_select_wireguard_client || { pause; return 1; }
            ;;
        2)
            echo
            echo "Enter one source IPv4 address or IPv4 CIDR network."
            echo "Examples: 10.250.0.2 or 192.168.10.0/24. Do not enter a URL or port."
            read -r -p "Source IPv4/CIDR: " value
            if valid_ipv4 "${value}"; then
                ACCESS_SOURCE_VALUE="${value}/32"
            elif valid_cidr "${value}"; then
                ACCESS_SOURCE_VALUE="$(cidr_normalized "${value}")"
            else
                error "Source must be a valid IPv4 address or IPv4 CIDR."
                pause
                return 1
            fi
            ACCESS_SOURCE_IP="$(access_check_first_ip "${ACCESS_SOURCE_VALUE}")"
            ACCESS_SOURCE_LABEL="custom source"
            suggested="$(access_check_suggest_interface "${ACCESS_SOURCE_IP}")"
            access_check_select_interface "${suggested}" || { pause; return 1; }
            ;;
        b|B|0|"") return 1 ;;
        e|E) clear_screen; echo "Bye."; exit 0 ;;
        *) error "Invalid selection."; pause; return 1 ;;
    esac
}

access_check_collect_destination() {
    local choice value protocol port
    banner
    section "ACCESS CHECK - DESTINATION"
    cat <<'EOF'
Select what the source should be able to reach:

  [1] Entire IPv4 Internet (route probe uses 1.1.1.1)
  [2] One destination IPv4 address
  [3] One destination IPv4 CIDR network
  [4] TCP/UDP service on this Debian server
  [B] Back
  [E] Exit

Internet/host/network selections evaluate a forwarded path through this server.
The local-service selection evaluates an INPUT path to a TCP/UDP port on it.
No selection creates a firewall rule.
EOF
    echo
    read -r -p "Destination: " choice
    case "${choice}" in
        1)
            ACCESS_CHECK_MODE="internet"
            ACCESS_DEST_LABEL="entire IPv4 Internet"
            ACCESS_DEST_VALUE="0.0.0.0/0"
            ACCESS_DEST_IP="1.1.1.1"
            ACCESS_NEEDS_NAT=1
            ;;
        2)
            ACCESS_CHECK_MODE="forward"
            echo
            echo "Enter only one IPv4 address, for example 10.200.200.10."
            read -r -p "Destination IPv4: " value
            valid_ipv4 "${value}" || { error "Invalid destination IPv4 address."; pause; return 1; }
            ACCESS_DEST_LABEL="destination host"
            ACCESS_DEST_VALUE="${value}/32"
            ACCESS_DEST_IP="${value}"
            ACCESS_NEEDS_NAT=0
            ;;
        3)
            ACCESS_CHECK_MODE="forward"
            echo
            echo "Enter one IPv4 CIDR, for example 10.200.200.0/24."
            echo "The route probe uses the first usable address in that network."
            read -r -p "Destination IPv4 CIDR: " value
            valid_cidr "${value}" || { error "Invalid destination IPv4 CIDR."; pause; return 1; }
            ACCESS_DEST_VALUE="$(cidr_normalized "${value}")"
            ACCESS_DEST_IP="$(access_check_first_ip "${ACCESS_DEST_VALUE}")"
            ACCESS_DEST_LABEL="destination network"
            ACCESS_NEEDS_NAT=0
            ;;
        4)
            ACCESS_CHECK_MODE="local_service"
            echo
            echo "Choose the transport protocol used by the local service."
            echo "Use TCP for SSH/HTTP/HTTPS and UDP for services such as DNS or WireGuard."
            read -r -p "Protocol [tcp]: " protocol
            case "${protocol}" in
                b|B) return 1 ;;
                e|E) clear_screen; echo "Bye."; exit 0 ;;
            esac
            protocol="$(tr '[:upper:]' '[:lower:]' <<< "${protocol:-tcp}")"
            [[ "${protocol}" == "tcp" || "${protocol}" == "udp" ]] || { error "Protocol must be tcp or udp."; pause; return 1; }
            echo
            echo "Enter the local destination port from 1 through 65535."
            echo "Examples: 22 for SSH, 80 for HTTP, 443 for HTTPS or 8851 for your local service."
            read -r -p "Local destination port: " port
            case "${port}" in
                b|B) return 1 ;;
                e|E) clear_screen; echo "Bye."; exit 0 ;;
            esac
            valid_port "${port}" || { error "Port must be between 1 and 65535."; pause; return 1; }
            ACCESS_SERVICE_PROTO="${protocol}"
            ACCESS_SERVICE_PORT="$((10#${port}))"
            ACCESS_DEST_LABEL="service on this Debian server"
            ACCESS_DEST_VALUE="${ACCESS_SERVICE_PROTO}/${ACCESS_SERVICE_PORT}"
            ACCESS_DEST_IP="local"
            ACCESS_NEEDS_NAT=0
            ;;
        b|B|0|"") return 1 ;;
        e|E) clear_screen; echo "Bye."; exit 0 ;;
        *) error "Invalid selection."; pause; return 1 ;;
    esac
}

access_check_local_service() {
    local sockets="" ufw_status="" default_incoming="" input_policy="" proto_upper
    proto_upper="$(tr '[:lower:]' '[:upper:]' <<< "${ACCESS_SERVICE_PROTO}")"

    section "LOCAL SERVICE"
    if command_available ss; then
        if [[ "${ACCESS_SERVICE_PROTO}" == "tcp" ]]; then
            sockets="$(ss -H -lnt "sport = :${ACCESS_SERVICE_PORT}" 2>/dev/null || true)"
        else
            sockets="$(ss -H -lnu "sport = :${ACCESS_SERVICE_PORT}" 2>/dev/null || true)"
        fi
        if [[ -z "${sockets}" ]]; then
            access_check_fail "No local ${proto_upper} listener was found on port ${ACCESS_SERVICE_PORT}."
        elif grep -Ev '127\.0\.0\.1:|\[::1\]:' <<< "${sockets}" | grep -q '[^[:space:]]'; then
            access_check_ok "A non-loopback ${proto_upper} listener exists on port ${ACCESS_SERVICE_PORT}."
            printf '%s\n' "${sockets}" | sed 's/^/    /'
        else
            access_check_fail "Port ${ACCESS_SERVICE_PORT}/${ACCESS_SERVICE_PROTO} listens only on loopback."
            printf '%s\n' "${sockets}" | sed 's/^/    /'
        fi
    else
        access_check_warn "The ss command is unavailable; local listener state could not be checked."
    fi

    section "LOCAL INPUT FIREWALL"
    if ufw_installed && ufw_active; then
        ufw_status="$(ufw status verbose 2>/dev/null || true)"
        default_incoming="$(grep -E '^Default:' <<< "${ufw_status}" | head -1)"
        if access_check_ufw_allows_local_service "${ACCESS_SERVICE_PORT}" "${ACCESS_SERVICE_PROTO}" "${ACCESS_SOURCE_VALUE}"; then
            access_check_ok "UFW has an ALLOW IN rule covering ${ACCESS_SOURCE_VALUE} to ${ACCESS_SERVICE_PORT}/${ACCESS_SERVICE_PROTO}."
        elif grep -Eiq 'allow[[:space:]]*\(incoming\)' <<< "${default_incoming}"; then
            access_check_ok "UFW default incoming policy is ALLOW."
        else
            access_check_fail "UFW is active with default incoming DENY and no matching ALLOW IN rule was found."
        fi
    else
        if ufw_installed; then
            info "UFW is installed but inactive; it does not currently filter this local service."
        else
            info "UFW is not installed; no UFW decision applies to this local service."
        fi
        if command_available iptables; then
            input_policy="$(iptables -S INPUT 2>/dev/null | head -1)"
            if [[ "${input_policy}" == "-P INPUT ACCEPT" ]]; then
                access_check_ok "Live iptables INPUT default policy is ACCEPT."
            else
                access_check_warn "Live INPUT policy is not plainly ACCEPT; specific nftables/iptables rules require review."
            fi
        else
            access_check_warn "Low-level INPUT firewall policy could not be checked."
        fi
    fi
}

access_check_print_result() {
    local headline service_proto_upper
    section "RESULT"
    printf '%-18s %d\n' "Confirmed checks:" "${ACCESS_CHECK_OK}"
    printf '%-18s %d\n' "Warnings/unknown:" "${ACCESS_CHECK_WARN}"
    printf '%-18s %d\n' "Blocking failures:" "${ACCESS_CHECK_FAIL}"
    echo

    case "${ACCESS_CHECK_MODE}" in
        internet) headline="INTERNET ACCESS" ;;
        local_service)
            service_proto_upper="$(tr '[:lower:]' '[:upper:]' <<< "${ACCESS_SERVICE_PROTO}")"
            headline="LOCAL SERVICE ACCESS ${service_proto_upper}/${ACCESS_SERVICE_PORT}"
            ;;
        *) headline="ROUTED NETWORK ACCESS" ;;
    esac

    if (( ACCESS_CHECK_FAIL > 0 )); then
        printf '%b%s: BLOCKED OR INCOMPLETE%b\n' "${C_RED}${C_BOLD}" "${headline}" "${C_RESET}"
        error "At least one blocking server-side configuration problem was detected."
    elif (( ACCESS_CHECK_WARN > 0 )); then
        printf '%b%s: NOT FULLY CONFIRMED%b\n' "${C_YELLOW}${C_BOLD}" "${headline}" "${C_RESET}"
        warn "No definite blocker was found, but the server-side path is not fully proven."
    else
        printf '%b%s: CONFIGURED%b\n' "${C_GREEN}${C_BOLD}" "${headline}" "${C_RESET}"
        ok "All server-side checks available to the manager passed."
    fi
    echo
    info "This is a read-only server-side configuration check, not an end-to-end test from the remote client."
    info "No firewall rule, route, interface or system setting was changed."
    pause
}

access_check_run() {
    local route simulated=1 egress="" forwarding="" ufw_status="" ufw_rules="" default_routed=""
    local wg_dump="" peer="" export_file="" nat_source="${ACCESS_SOURCE_VALUE}"
    local link_line="" link_flags="" forward_allow=0

    ACCESS_CHECK_OK=0
    ACCESS_CHECK_WARN=0
    ACCESS_CHECK_FAIL=0
    banner
    section "READ-ONLY ACCESS CHECK"
    printf '%-24s %s (%s)\n' "Source:" "${ACCESS_SOURCE_LABEL}" "${ACCESS_SOURCE_VALUE}"
    printf '%-24s %s\n' "Ingress interface:" "${ACCESS_INGRESS_IF}"
    printf '%-24s %s (%s)\n' "Destination:" "${ACCESS_DEST_LABEL}" "${ACCESS_DEST_VALUE}"
    [[ "${ACCESS_CHECK_MODE}" != "local_service" ]] && printf '%-24s %s\n' "Route probe address:" "${ACCESS_DEST_IP}"
    echo

    section "INTERFACE AND SOURCE"
    if ip link show "${ACCESS_INGRESS_IF}" >/dev/null 2>&1; then
        access_check_ok "Ingress interface ${ACCESS_INGRESS_IF} exists."
        link_line="$(ip link show "${ACCESS_INGRESS_IF}" 2>/dev/null | head -1)"
        link_flags="$(sed -n 's/.*<\([^>]*\)>.*/\1/p' <<< "${link_line}")"
        if [[ ",${link_flags}," == *,UP,* ]]; then
            access_check_ok "Ingress interface ${ACCESS_INGRESS_IF} is UP."
        else
            access_check_fail "Ingress interface ${ACCESS_INGRESS_IF} does not have the UP flag."
        fi
    else
        access_check_fail "Ingress interface ${ACCESS_INGRESS_IF} does not exist."
    fi

    if [[ -n "${ACCESS_WG_CLIENT_ID}" ]]; then
        if command_available wg && wg show "${ACCESS_INGRESS_IF}" >/dev/null 2>&1; then
            access_check_ok "WireGuard interface ${ACCESS_INGRESS_IF} is active."
            wg_dump="$(wg show "${ACCESS_INGRESS_IF}" dump 2>/dev/null || true)"
            peer="$(awk -F'\t' -v p="${WG_CLIENT_PUBLIC_KEY}" '$1==p{print; exit}' <<< "${wg_dump}")"
            if [[ -n "${peer}" ]]; then
                access_check_ok "WireGuard peer for ${WG_CLIENT_NAME} is loaded."
            else
                access_check_fail "WireGuard peer for ${WG_CLIENT_NAME} is not loaded on ${ACCESS_INGRESS_IF}."
            fi
        else
            access_check_fail "WireGuard interface ${ACCESS_INGRESS_IF} is not active."
        fi
        export_file="$(wireguard_client_export_file "${ACCESS_WG_CLIENT_ID}")"
        if [[ -f "${export_file}" ]] && grep -Eq '^AllowedIPs[[:space:]]*=[[:space:]]*0\.0\.0\.0/0([[:space:]]|$)' "${export_file}"; then
            access_check_ok "Client export is full-tunnel (AllowedIPs includes all IPv4 destinations)."
        elif [[ -f "${export_file}" ]]; then
            access_check_warn "Client export is not full-tunnel; verify that ${ACCESS_DEST_VALUE} is included in AllowedIPs."
        else
            access_check_warn "No client export is available; client-side AllowedIPs cannot be verified."
        fi
        [[ -n "${WG_NETWORK:-}" ]] && nat_source="${WG_NETWORK}"
    fi

    if [[ "${ACCESS_CHECK_MODE}" == "local_service" ]]; then
        access_check_local_service
        access_check_print_result
        return
    fi

    section "FORWARDING AND ROUTE"
    forwarding="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo unknown)"
    if [[ "${forwarding}" == "1" ]]; then
        access_check_ok "IPv4 forwarding is enabled."
    elif [[ "${forwarding}" == "0" ]]; then
        access_check_fail "IPv4 forwarding is disabled. Forwarded client traffic cannot pass."
    else
        access_check_warn "IPv4 forwarding state could not be read."
    fi

    route="$(ip -4 route get "${ACCESS_DEST_IP}" from "${ACCESS_SOURCE_IP}" iif "${ACCESS_INGRESS_IF}" 2>/dev/null || true)"
    if [[ -z "${route}" ]]; then
        simulated=0
        route="$(ip -4 route get "${ACCESS_DEST_IP}" 2>/dev/null || true)"
    fi
    if [[ -z "${route}" ]] || grep -Eq '(^|[[:space:]])(unreachable|prohibit|blackhole)([[:space:]]|$)' <<< "${route}"; then
        access_check_fail "No usable IPv4 route to ${ACCESS_DEST_IP} was found."
    else
        egress="$(awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' <<< "${route}")"
        access_check_ok "Route to ${ACCESS_DEST_IP} exists${egress:+ via ${egress}}."
        printf '    %s\n' "${route}"
        (( simulated == 1 )) || access_check_warn "Kernel rejected the forwarded-packet simulation; displayed route is a local fallback lookup."
    fi

    section "FORWARD FIREWALL"
    if command_available iptables; then
        if iptables -C FORWARD -i "${ACCESS_INGRESS_IF}" -j ACCEPT >/dev/null 2>&1; then
            forward_allow=1
            access_check_ok "iptables contains an ingress FORWARD allow rule for ${ACCESS_INGRESS_IF}."
        else
            access_check_warn "No simple iptables 'FORWARD -i ${ACCESS_INGRESS_IF} -j ACCEPT' rule was found."
            info "A more specific nftables/iptables rule may still permit this path."
        fi
    else
        access_check_warn "iptables is unavailable; low-level FORWARD rules were not checked."
    fi

    if ufw_installed; then
        if ufw_active; then
            ufw_status="$(ufw status verbose 2>/dev/null || true)"
            ufw_rules="$(ufw status numbered 2>/dev/null || true)"
            default_routed="$(grep -E '^Default:' <<< "${ufw_status}" | head -1)"
            if grep -Eiq 'allow[[:space:]]*\(routed\)' <<< "${default_routed}"; then
                access_check_ok "UFW default routed policy is ALLOW."
            elif grep -Eiq 'deny[[:space:]]*\(routed\)' <<< "${default_routed}"; then
                if (( forward_allow == 1 )) && ! grep -Eq 'ALLOW FWD|DENY FWD|REJECT FWD|LIMIT FWD' <<< "${ufw_rules}"; then
                    access_check_ok "UFW routed default is DENY, but the live explicit iptables rule allows ingress forwarding from ${ACCESS_INGRESS_IF}."
                    info "The explicit live FORWARD rule is the effective allow evidence for this path."
                elif (( forward_allow == 1 )); then
                    access_check_warn "An explicit iptables ingress allow exists, but UFW also has ordered FWD rules."
                    info "Their source/destination match and order require a more detailed rule evaluator."
                else
                    access_check_warn "UFW routed default is DENY and no simple explicit ingress FORWARD allow rule was found."
                    info "A more specific UFW/nftables/iptables rule may still allow the selected source and destination."
                fi
            else
                access_check_warn "UFW routed default policy could not be determined."
            fi
        else
            access_check_ok "UFW is installed but inactive, so it does not currently block this path."
        fi
    else
        info "UFW is not installed; no UFW decision applies. Provider and low-level firewalls remain separate."
    fi

    if (( ACCESS_NEEDS_NAT == 1 )); then
        section "INTERNET NAT"
        if [[ -z "${egress}" ]]; then
            access_check_fail "Internet egress interface is unknown, so NAT cannot be verified."
        elif command_available iptables && iptables -t nat -C POSTROUTING -s "${nat_source}" -o "${egress}" -j MASQUERADE >/dev/null 2>&1; then
            access_check_ok "MASQUERADE exists for ${nat_source} via ${egress}."
        else
            access_check_warn "No exact MASQUERADE rule for ${nat_source} via ${egress} was found."
            info "A broader nftables/iptables NAT rule may still cover this source."
        fi
    fi

    access_check_print_result
}

access_check_menu() {
    local choice
    while :; do
        banner
        section "ACCESS CHECK (READ-ONLY)"
        cat <<'EOF'
Analyse a forwarded IPv4 path without changing firewall rules, routes,
interfaces or system settings.

  [1] Start a new access check
  [B] Back to main menu
  [E] Exit
EOF
        echo
        read -r -p "Selection: " choice
        case "${choice}" in
            1)
                access_check_collect_source || continue
                access_check_collect_destination || continue
                access_check_run
                ;;
            b|B|0|"") return ;;
            e|E) clear_screen; echo "Bye."; exit 0 ;;
            *) error "Invalid selection."; sleep 1 ;;
        esac
    done
}

# ==============================================================================
# Read-only iptables / packet-filter diagnostics
# ==============================================================================

iptables_require_readonly_tools() {
    if ! command_available iptables; then
        error "iptables is not available on this server."
        info "On modern Debian systems it normally provides the nftables-compatible iptables view."
        pause
        return 1
    fi
}

iptables_backend_label() {
    local version
    version="$(iptables --version 2>/dev/null || true)"
    case "${version}" in
        *nf_tables*) printf 'nftables backend (iptables-nft)' ;;
        *legacy*) printf 'legacy iptables backend' ;;
        *) printf 'backend not identified' ;;
    esac
}

iptables_chain_policy() {
    local table="$1" chain="$2" policy
    policy="$(iptables -t "${table}" -S "${chain}" 2>/dev/null | awk -v c="${chain}" '$1=="-P" && $2==c {print $3; exit}')"
    printf '%s' "${policy:-not available}"
}

iptables_rule_count() {
    local table="$1"
    iptables -t "${table}" -S 2>/dev/null | awk '$1=="-A" {count++} END {print count+0}'
}

iptables_show_overview() {
    local version forwarding docker_state="not installed"
    banner
    section "IPTABLES / PACKET FILTER OVERVIEW"
    iptables_require_readonly_tools || return

    info "Reading the live packet-filter state. On systems with UFW, Docker or many rules this may take a few seconds..."
    echo

    version="$(iptables --version 2>/dev/null || true)"
    forwarding="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo unknown)"
    if command_available docker; then
        if docker info >/dev/null 2>&1; then docker_state="running"; else docker_state="installed, daemon unavailable"; fi
    fi

    printf '%-30s %s\n' "iptables version:" "${version:-unknown}"
    printf '%-30s %s\n' "Rule backend:" "$(iptables_backend_label)"
    printf '%-30s %s\n' "IPv4 forwarding:" "${forwarding}"
    printf '%-30s %s\n' "UFW:" "$(if ! ufw_installed; then echo 'not installed'; elif ufw_active; then echo active; else echo inactive; fi)"
    printf '%-30s %s\n' "Docker:" "${docker_state}"

    section "DEFAULT FILTER POLICIES"
    printf '%-16s %s\n' "INPUT" "$(iptables_chain_policy filter INPUT)"
    printf '%-16s %s\n' "FORWARD" "$(iptables_chain_policy filter FORWARD)"
    printf '%-16s %s\n' "OUTPUT" "$(iptables_chain_policy filter OUTPUT)"

    section "RULE COUNTS"
    printf '%-16s %s\n' "filter" "$(iptables_rule_count filter)"
    printf '%-16s %s\n' "nat" "$(iptables_rule_count nat)"
    printf '%-16s %s\n' "mangle" "$(iptables_rule_count mangle)"
    echo
    info "Counters and rules shown here are the live IPv4 packet-filter state."
    info "No firewall rule or policy was changed."
    pause
}

iptables_show_filter_rules() {
    local chain
    banner
    section "FILTER RULES / FORWARDING"
    iptables_require_readonly_tools || return
    for chain in INPUT FORWARD OUTPUT; do
        section "${chain} CHAIN"
        if ! iptables -L "${chain}" -n -v --line-numbers 2>&1; then
            warn "The ${chain} chain could not be displayed."
        fi
    done
    echo
    info "Rules are displayed in evaluation order with packet and byte counters."
    info "No firewall rule or policy was changed."
    pause
}

iptables_show_nat_rules() {
    banner
    section "NAT / DNAT / MASQUERADE"
    iptables_require_readonly_tools || return
    if ! iptables -t nat -L -n -v --line-numbers 2>&1; then
        warn "The IPv4 nat table could not be displayed."
    fi
    section "EXACT NAT RULE SYNTAX"
    iptables -t nat -S 2>&1 || true
    echo
    info "DNAT changes the destination before FORWARD filtering; MASQUERADE/SNAT changes the source on egress."
    info "No NAT rule was changed."
    pause
}

iptables_show_docker_rules() {
    local chain
    banner
    section "DOCKER PORTS AND FIREWALL CHAINS"
    iptables_require_readonly_tools || return
    if command_available docker; then
        section "PUBLISHED CONTAINER PORTS"
        docker ps --format 'table {{.Names}}\t{{.Networks}}\t{{.Ports}}' 2>&1 || warn "Docker is installed, but its daemon could not be queried."
    else
        info "Docker is not installed. Live Docker-created chains may still be shown below if they exist."
    fi
    for chain in DOCKER DOCKER-USER DOCKER-FORWARD; do
        section "${chain}"
        if [[ "${chain}" == "DOCKER" ]]; then
            iptables -t nat -S "${chain}" 2>/dev/null || info "Chain ${chain} is not present in the nat table."
        else
            iptables -S "${chain}" 2>/dev/null || info "Chain ${chain} is not present in the filter table."
        fi
    done
    echo
    info "A published container port normally uses DNAT and therefore traverses FORWARD, not INPUT."
    info "No Docker or firewall setting was changed."
    pause
}

iptables_show_vpn_rules() {
    local output
    banner
    section "S2S / WIREGUARD PACKET-FILTER RULES"
    iptables_require_readonly_tools || return
    output="$(iptables-save -c 2>/dev/null | grep -Ei '(^|[[:space:]])(-i|-o)[[:space:]]+(wg|ipsec|vti)|10\.200\.|10\.240\.|10\.250\.|MASQUERADE' || true)"
    if [[ -n "${output}" ]]; then
        printf '%s\n' "${output}"
    else
        info "No obvious IPv4 rule containing a wg/ipsec/vti interface, known VPN subnet or MASQUERADE was found."
    fi
    section "POLICY-ROUTING CONTEXT (TABLE 220)"
    ip -4 route show table 220 2>/dev/null || info "Routing table 220 is unavailable or empty."
    echo
    info "This is a filtered diagnostic view; use the complete filter/NAT views for rule order."
    info "No firewall or routing state was changed."
    pause
}

iptables_find_dnat_rule() {
    local destination="$1" protocol="$2" port="$3"
    iptables -t nat -S 2>/dev/null | awk -v destination="${destination}" -v protocol="${protocol}" -v port="${port}" '
        $1 == "-A" {
            dest=""; proto=""; dport=""; jump=""; target=""
            for (i=1; i<=NF; i++) {
                if ($i=="-d") dest=$(i+1)
                else if ($i=="-p") proto=$(i+1)
                else if ($i=="--dport") dport=$(i+1)
                else if ($i=="-j") jump=$(i+1)
                else if ($i=="--to-destination") target=$(i+1)
            }
            sub(/\/32$/, "", dest)
            if (jump=="DNAT" && (dest=="" || dest=="0.0.0.0/0" || dest==destination) && proto==protocol && dport==port && target!="") {
                print target "\t" $0
            }
        }'
}

iptables_is_local_ipv4() {
    local address="$1" cidr
    while read -r cidr; do
        [[ "${cidr%%/*}" == "${address}" ]] && return 0
    done < <(ip -o -4 addr show 2>/dev/null | awk '{print $4}')
    return 1
}

iptables_show_relevant_rules() {
    local source="$1" destination="$2" protocol="$3" port="$4" ingress="$5"
    local candidates
    candidates="$(iptables-save -c 2>/dev/null | grep -E "${source//./\\.}|${destination//./\\.}|--dport ${port}([[:space:]]|$)|-i ${ingress}([[:space:]]|$)" | grep -E -- "-p ${protocol}([[:space:]]|$)|${source//./\\.}|${destination//./\\.}|-i ${ingress}([[:space:]]|$)" || true)"
    if [[ -n "${candidates}" ]]; then
        printf '%s\n' "${candidates}"
    else
        info "No rule containing the selected source, destination, port or ingress interface was found."
    fi
}

iptables_analyze_packet_path() {
    local source destination protocol port ingress suggested dnat_data dnat_first target rule
    local target_ip target_port route path verdict
    banner
    section "ANALYZE PACKET PATH (READ-ONLY)"
    iptables_require_readonly_tools || return
    cat <<'EOF'
Describe the packet as it arrives at this server. For a published Docker
service, enter the server/VTI address and public port used by the client,
not the container address. The manager detects an exact IPv4 DNAT rule.

This analysis reads live rules and routes. It sends no packet and changes
no firewall, Docker, VPN, interface or routing configuration.
EOF
    echo
    read -r -p "Remote source IPv4: " source
    case "${source}" in b|B|"") return ;; e|E) clear_screen; echo "Bye."; exit 0 ;; esac
    valid_ipv4 "${source}" || { error "Enter one plain source IPv4 address, without CIDR, URL or port."; pause; return; }

    ACCESS_SOURCE_VALUE="${source}/32"
    suggested="$(access_check_suggest_interface "${source}")"
    access_check_select_interface "${suggested}" || return
    ingress="${ACCESS_INGRESS_IF}"

    echo
    echo "Enter the IPv4 address to which the client connects before possible DNAT."
    echo "Example: the server VTI address 10.200.204.1 for 10.200.204.1:5341."
    read -r -p "Original destination IPv4: " destination
    case "${destination}" in b|B|"") return ;; e|E) clear_screen; echo "Bye."; exit 0 ;; esac
    valid_ipv4 "${destination}" || { error "Enter one plain destination IPv4 address."; pause; return; }

    while :; do
        read -r -p "Protocol [tcp]: " protocol
        case "${protocol}" in b|B) return ;; e|E) clear_screen; echo "Bye."; exit 0 ;; esac
        protocol="$(tr '[:upper:]' '[:lower:]' <<< "${protocol:-tcp}")"
        if [[ "${protocol}" == "tcp" || "${protocol}" == "udp" ]]; then
            break
        fi
        error "Protocol must be tcp or udp. Please try again, or enter B to go back."
    done
    read -r -p "Destination port (1-65535): " port
    case "${port}" in b|B|"") return ;; e|E) clear_screen; echo "Bye."; exit 0 ;; esac
    valid_port "${port}" || { error "Port must be between 1 and 65535."; pause; return; }
    port="$((10#${port}))"

    dnat_data="$(iptables_find_dnat_rule "${destination}" "${protocol}" "${port}")"
    dnat_first="$(head -1 <<< "${dnat_data}")"
    target="${dnat_first%%$'\t'*}"
    rule="${dnat_first#*$'\t'}"

    banner
    section "PACKET PATH RESULT"
    printf '%-28s %s\n' "Source:" "${source}"
    printf '%-28s %s\n' "Ingress interface:" "${ingress}"
    printf '%-28s %s/%s\n' "Original destination:" "${destination}" "${port}"
    printf '%-28s %s\n' "Protocol:" "${protocol^^}"

    if [[ -n "${dnat_first}" ]]; then
        target_ip="${target%%:*}"
        target_port="${target##*:}"
        [[ "${target}" == "${target_ip}" ]] && target_port="${port}"
        path="PREROUTING/DNAT -> FORWARD -> ${target_ip}:${target_port}"
        verdict="DNAT/FORWARD PATH DETECTED"
        section "DNAT DECISION"
        ok "Exact DNAT rule found. The packet is filtered through FORWARD, not INPUT."
        printf '%-28s %s\n' "Translated destination:" "${target_ip}:${target_port}"
        printf '%-28s %s\n' "Packet path:" "${path}"
        echo "    ${rule}"
        section "ROUTE TO TRANSLATED TARGET"
        route="$(ip -4 route get "${target_ip}" from "${source}" iif "${ingress}" 2>/dev/null || ip -4 route get "${target_ip}" 2>/dev/null || true)"
        if [[ -n "${route}" ]]; then ok "A route to ${target_ip} exists."; echo "    ${route}"; else error "No route to ${target_ip} was found."; fi
        if command_available docker; then
            section "MATCHING DOCKER PORT PUBLICATION"
            docker ps --format '{{.Names}}  {{.Ports}}' 2>/dev/null | grep -F "${destination}:${port}->${target_port}/" || info "No matching running Docker publication was identified."
        fi
    elif iptables_is_local_ipv4 "${destination}"; then
        path="INPUT (local address; no exact DNAT rule found)"
        verdict="LOCAL INPUT PATH DETECTED"
        section "PATH DECISION"
        ok "The destination belongs to this server and no exact DNAT rule was found."
        printf '%-28s %s\n' "Packet path:" "${path}"
        section "LOCAL LISTENER"
        if command_available ss && ss -H -ln"${protocol:0:1}" "sport = :${port}" 2>/dev/null | grep -q .; then
            ok "A local ${protocol^^} listener exists on port ${port}."
            ss -H -ln"${protocol:0:1}" "sport = :${port}" 2>/dev/null | sed 's/^/    /'
        else
            warn "No local ${protocol^^} listener was found on port ${port}."
        fi
    else
        path="FORWARD (routed destination; no exact DNAT rule found)"
        verdict="ROUTED FORWARD PATH DETECTED"
        section "PATH DECISION"
        info "The destination is not a local IPv4 address and no exact DNAT rule was found."
        printf '%-28s %s\n' "Packet path:" "${path}"
        section "ROUTE TO DESTINATION"
        route="$(ip -4 route get "${destination}" from "${source}" iif "${ingress}" 2>/dev/null || ip -4 route get "${destination}" 2>/dev/null || true)"
        if [[ -n "${route}" ]]; then ok "A route to ${destination} exists."; echo "    ${route}"; else error "No route to ${destination} was found."; fi
    fi

    section "RELEVANT LIVE RULE CANDIDATES"
    iptables_show_relevant_rules "${source}" "${target_ip:-${destination}}" "${protocol}" "${target_port:-${port}}" "${ingress}"
    if ufw_installed; then
        section "UFW FORWARD / INPUT CANDIDATES"
        ufw status numbered 2>/dev/null | grep -E "ALLOW (FWD|IN)|DENY (FWD|IN)|REJECT (FWD|IN)" || info "No formatted UFW allow/deny candidates are visible."
    fi
    section "ASSESSMENT"
    printf '%b%s%b\n' "${C_CYAN}${C_BOLD}" "${verdict}" "${C_RESET}"
    info "The detected chain and route are shown above. A read-only inspection cannot prove the final ordered firewall verdict or remote service response."
    info "Test from the actual client for end-to-end confirmation. No state was changed."
    pause
}

iptables_management_menu() {
    local choice
    while :; do
        banner
        section "IPTABLES / PACKET FILTER (READ-ONLY)"
        cat <<'EOF'
Inspect the live IPv4 packet-filter, NAT and Docker/VPN rule state.
This section never adds, deletes, flushes or changes a rule or policy.

  [1] Overview and default policies
  [2] Filter rules (INPUT / FORWARD / OUTPUT)
  [3] NAT / DNAT / MASQUERADE rules
  [4] Docker rules and published ports
  [5] S2S / WireGuard-related rules
  [6] Analyze source -> destination -> port
  [B] Back to main menu
  [E] Exit
EOF
        echo
        read -r -p "Selection: " choice
        case "${choice}" in
            1) iptables_show_overview ;;
            2) iptables_show_filter_rules ;;
            3) iptables_show_nat_rules ;;
            4) iptables_show_docker_rules ;;
            5) iptables_show_vpn_rules ;;
            6) iptables_analyze_packet_path ;;
            b|B|0|"") return ;;
            e|E) clear_screen; echo "Bye."; exit 0 ;;
            *) error "Invalid selection."; sleep 1 ;;
        esac
    done
}

# End read-only iptables / packet-filter diagnostics

# ==============================================================================
# Cron / scheduled-task management
# ==============================================================================

CRON_JOB_COUNT=0
CRON_MALFORMED_COUNT=0
CRON_HUMAN_READABLE=1
CRON_JOB_SOURCE=()
CRON_JOB_SOURCE_LABEL=()
CRON_JOB_SOURCE_HASH=()
CRON_JOB_START=()
CRON_JOB_END=()
CRON_JOB_MANAGED=()
CRON_JOB_STATUS=()
CRON_JOB_NAME=()
CRON_JOB_SCHEDULE=()
CRON_JOB_USER=()
CRON_JOB_COMMAND=()
CRON_JOB_RAW=()
CRON_JOB_READABLE_MATCH=()
CRON_MALFORMED_SOURCE_LIST=""
CRON_SOURCE_ERROR_COUNT=0

cron_command_available() {
    command_available crontab
}

cron_source_is_system() {
    [[ "$1" != user:* ]]
}

cron_source_label() {
    local source="$1"
    case "${source}" in
        user:*) printf '%s crontab' "${source#user:}" ;;
        file:/etc/crontab) printf '/etc/crontab' ;;
        file:*) printf '%s' "${source#file:}" ;;
    esac
}

cron_list_sources() {
    local file user
    printf 'user:root\n'
    if [[ -d /var/spool/cron/crontabs ]]; then
        for file in /var/spool/cron/crontabs/*; do
            [[ -f "${file}" ]] || continue
            user="$(basename "${file}")"
            [[ "${user}" == "root" ]] && continue
            id "${user}" >/dev/null 2>&1 && printf 'user:%s\n' "${user}"
        done
    fi
    [[ -r /etc/crontab ]] && printf 'file:/etc/crontab\n'
    if [[ -d /etc/cron.d ]]; then
        for file in /etc/cron.d/*; do
            [[ -f "${file}" && -r "${file}" ]] || continue
            [[ "$(basename "${file}")" =~ ^[A-Za-z0-9_-]+$ ]] || continue
            printf 'file:%s\n' "${file}"
        done
    fi
}

cron_read_source_to_file() {
    local source="$1" destination="$2" user path spool
    case "${source}" in
        user:*)
            user="${source#user:}"
            spool="/var/spool/cron/crontabs/${user}"
            if cron_command_available; then
                if crontab -u "${user}" -l > "${destination}" 2>/dev/null; then
                    return 0
                fi
                [[ ! -f "${spool}" ]] || return 1
            elif [[ -f "${spool}" && -r "${spool}" ]]; then
                cp -- "${spool}" "${destination}"
                return
            fi
            : > "${destination}"
            return 0
            ;;
        file:*)
            path="${source#file:}"
            [[ -f "${path}" ]] || return 1
            cp -- "${path}" "${destination}"
            ;;
        *) return 1 ;;
    esac
}

cron_file_hash() {
    cksum "$1" 2>/dev/null | awk '{print $1 ":" $2}'
}

cron_valid_field() {
    local value="$1" position="${2:-1}" upper min max number normalized
    upper="$(tr '[:lower:]' '[:upper:]' <<< "${value}")"
    case "${position}" in
        1) min=0; max=59; normalized="${upper}" ;;
        2) min=0; max=23; normalized="${upper}" ;;
        3) min=1; max=31; normalized="${upper}" ;;
        4)
            min=1; max=12
            normalized="${upper//JAN/1}"; normalized="${normalized//FEB/2}"; normalized="${normalized//MAR/3}"
            normalized="${normalized//APR/4}"; normalized="${normalized//MAY/5}"; normalized="${normalized//JUN/6}"
            normalized="${normalized//JUL/7}"; normalized="${normalized//AUG/8}"; normalized="${normalized//SEP/9}"
            normalized="${normalized//OCT/10}"; normalized="${normalized//NOV/11}"; normalized="${normalized//DEC/12}"
            ;;
        5)
            min=0; max=7
            normalized="${upper//SUN/0}"; normalized="${normalized//MON/1}"; normalized="${normalized//TUE/2}"
            normalized="${normalized//WED/3}"; normalized="${normalized//THU/4}"; normalized="${normalized//FRI/5}"
            normalized="${normalized//SAT/6}"
            ;;
        *) return 1 ;;
    esac
    [[ "${normalized}" =~ ^[0-9*/,_-]+$ ]] || return 1
    [[ ! "${normalized}" =~ /0([^0-9]|$) ]] || return 1
    while read -r number; do
        [[ -n "${number}" ]] || continue
        (( 10#${number} >= min && 10#${number} <= max )) || return 1
    done < <(tr -cs '0-9' '\n' <<< "${normalized}")
    return 0
}

cron_parse_entry() {
    local line="$1" system_format="$2" f1 f2 f3 f4 f5 user command schedule
    CRON_PARSED_SCHEDULE=""
    CRON_PARSED_USER=""
    CRON_PARSED_COMMAND=""
    line="${line#"${line%%[![:space:]]*}"}"
    [[ -n "${line}" && "${line}" != \#* ]] || return 1
    [[ "${line}" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] && return 1

    if [[ "${line}" == @* ]]; then
        if [[ "${system_format}" == "1" ]]; then
            read -r schedule user command <<< "${line}"
            [[ -n "${schedule}" && -n "${user}" && -n "${command}" ]] || return 1
        else
            read -r schedule command <<< "${line}"
            [[ -n "${schedule}" && -n "${command}" ]] || return 1
        fi
        case "${schedule}" in
            @reboot|@yearly|@annually|@monthly|@weekly|@daily|@midnight|@hourly) ;;
            *) return 1 ;;
        esac
    else
        if [[ "${system_format}" == "1" ]]; then
            read -r f1 f2 f3 f4 f5 user command <<< "${line}"
            [[ -n "${f5}" && -n "${user}" && -n "${command}" ]] || return 1
        else
            read -r f1 f2 f3 f4 f5 command <<< "${line}"
            [[ -n "${f5}" && -n "${command}" ]] || return 1
        fi
        cron_valid_field "${f1}" 1 && cron_valid_field "${f2}" 2 && cron_valid_field "${f3}" 3 && \
            cron_valid_field "${f4}" 4 && cron_valid_field "${f5}" 5 || return 1
        schedule="${f1} ${f2} ${f3} ${f4} ${f5}"
    fi

    CRON_PARSED_SCHEDULE="${schedule}"
    CRON_PARSED_USER="${user:-}"
    CRON_PARSED_COMMAND="${command}"
}

cron_is_documentation_example() {
    local candidate="$1" normalized
    normalized="$(awk '{$1=$1; print}' <<< "${candidate}")"
    case "${normalized}" in
        '* * * * * user-name command to be executed') return 0 ;;
        *) return 1 ;;
    esac
}

cron_normalize_weekday_token() {
    local token
    token="$(tr '[:lower:]' '[:upper:]' <<< "$1")"
    case "${token}" in
        0|7|SUN|SUNDAY) printf '0' ;;
        1|MON|MONDAY) printf '1' ;;
        2|TUE|TUESDAY) printf '2' ;;
        3|WED|WEDNESDAY) printf '3' ;;
        4|THU|THURSDAY) printf '4' ;;
        5|FRI|FRIDAY) printf '5' ;;
        6|SAT|SATURDAY) printf '6' ;;
        *) return 1 ;;
    esac
}

cron_normalize_weekdays() {
    local input item first last normalized result="" seen="," part
    local -a parts=()
    input="$(tr -d '[:space:]' <<< "$1")"
    [[ -n "${input}" && "${input}" != ,* && "${input}" != *, && "${input}" != *,,* ]] || return 1
    IFS=',' read -r -a parts <<< "${input}"
    for item in "${parts[@]}"; do
        if [[ "${item}" == *-* ]]; then
            [[ "${item}" != -* && "${item}" != *- && "${item#*-}" != *-* ]] || return 1
            first="$(cron_normalize_weekday_token "${item%%-*}")" || return 1
            last="$(cron_normalize_weekday_token "${item#*-}")" || return 1
            (( first <= last )) || return 1
            [[ "${first}" == "${last}" ]] && part="${first}" || part="${first}-${last}"
        else
            part="$(cron_normalize_weekday_token "${item}")" || return 1
        fi
        [[ "${seen}" == *",${part},"* ]] && continue
        result="${result:+${result},}${part}"
        seen+="${part},"
    done
    [[ -n "${result}" ]] || return 1
    CRON_NORMALIZED_WEEKDAYS="${result}"
}

cron_weekday_name() {
    case "$1" in
        0|7) printf 'Sunday' ;; 1) printf 'Monday' ;; 2) printf 'Tuesday' ;; 3) printf 'Wednesday' ;;
        4) printf 'Thursday' ;; 5) printf 'Friday' ;; 6) printf 'Saturday' ;; *) printf '%s' "$1" ;;
    esac
}

cron_weekdays_readable() {
    local value="$1" item first last result="" text
    local -a parts=()
    IFS=',' read -r -a parts <<< "${value}"
    for item in "${parts[@]}"; do
        if [[ "${item}" == *-* ]]; then
            first="${item%%-*}"; last="${item#*-}"
            text="$(cron_weekday_name "${first}") through $(cron_weekday_name "${last}")"
        else
            text="$(cron_weekday_name "${item}")"
        fi
        result="${result:+${result}, }${text}"
    done
    printf '%s' "${result}"
}

cron_schedule_readable() {
    local schedule="$1" minute hour dom month dow n
    case "${schedule}" in
        @reboot) printf 'At system startup'; return ;;
        @yearly|@annually) printf 'Every year'; return ;;
        @monthly) printf 'Every month'; return ;;
        @weekly) printf 'Every week'; return ;;
        @daily|@midnight) printf 'Every day'; return ;;
        @hourly) printf 'Every hour'; return ;;
    esac
    read -r minute hour dom month dow <<< "${schedule}"
    if [[ "${minute}" =~ ^\*/([0-9]+)$ && "${hour} ${dom} ${month} ${dow}" == "* * * *" ]]; then
        n="${BASH_REMATCH[1]}"; printf 'Every %s minutes' "${n}"; return
    fi
    if [[ "${minute}" =~ ^[0-9]+$ && "${hour} ${dom} ${month} ${dow}" == "* * * *" ]]; then
        printf 'Every hour at minute %02d' "$((10#${minute}))"; return
    fi
    if [[ "${minute}" =~ ^[0-9]+$ && "${hour}" =~ ^[0-9]+$ && "${dom} ${month} ${dow}" == "* * *" ]]; then
        printf 'Every day at %02d:%02d' "$((10#${hour}))" "$((10#${minute}))"; return
    fi
    if [[ "${minute}" =~ ^[0-9]+$ && "${hour}" =~ ^[0-9]+$ && "${dom} ${month}" == "* *" && "${dow}" != "*" ]]; then
        printf 'On %s at %02d:%02d' "$(cron_weekdays_readable "${dow}")" "$((10#${hour}))" "$((10#${minute}))"; return
    fi
    if [[ "${minute}" =~ ^[0-9]+$ && "${hour}" =~ ^[0-9]+$ && "${dom}" =~ ^[0-9]+$ && "${month} ${dow}" == "* *" ]]; then
        printf 'Every month on day %s at %02d:%02d' "${dom}" "$((10#${hour}))" "$((10#${minute}))"; return
    fi
    printf 'Custom schedule: %s' "${schedule}"
}

cron_add_inventory_job() {
    CRON_JOB_COUNT=$((CRON_JOB_COUNT + 1))
    CRON_JOB_SOURCE[${CRON_JOB_COUNT}]="$1"
    CRON_JOB_SOURCE_LABEL[${CRON_JOB_COUNT}]="$2"
    CRON_JOB_SOURCE_HASH[${CRON_JOB_COUNT}]="$3"
    CRON_JOB_START[${CRON_JOB_COUNT}]="$4"
    CRON_JOB_END[${CRON_JOB_COUNT}]="$5"
    CRON_JOB_MANAGED[${CRON_JOB_COUNT}]="$6"
    CRON_JOB_STATUS[${CRON_JOB_COUNT}]="$7"
    CRON_JOB_NAME[${CRON_JOB_COUNT}]="$8"
    CRON_JOB_SCHEDULE[${CRON_JOB_COUNT}]="$9"
    shift 9
    CRON_JOB_USER[${CRON_JOB_COUNT}]="$1"
    CRON_JOB_COMMAND[${CRON_JOB_COUNT}]="$2"
    CRON_JOB_RAW[${CRON_JOB_COUNT}]="$3"
}

cron_inventory_source() {
    local source="$1" file="$2" hash="$3" source_label system_format=0 source_user=""
    local line candidate enabled readable job_name raw schedule command job_user
    local i=1 total=0 malformed_before="${CRON_MALFORMED_COUNT}"
    local -a lines=()
    source_label="$(cron_source_label "${source}")"
    cron_source_is_system "${source}" && system_format=1 || source_user="${source#user:}"
    while IFS= read -r line || [[ -n "${line}" ]]; do
        total=$((total + 1)); lines[${total}]="${line}"
    done < "${file}"

    while (( i <= total )); do
        line="${lines[$i]}"
        if [[ "${line}" == "# S2S-JOB:"* ]]; then
            job_name="${line#\# S2S-JOB: }"
            enabled="${lines[$((i + 1))]:-}"
            readable="${lines[$((i + 2))]:-}"
            raw="${lines[$((i + 3))]:-}"
            if [[ "${enabled}" != "# S2S-ENABLED: yes" && "${enabled}" != "# S2S-ENABLED: no" ]] || \
               [[ "${readable}" != "# S2S-READABLE:"* ]]; then
                CRON_MALFORMED_COUNT=$((CRON_MALFORMED_COUNT + 1)); i=$((i + 1)); continue
            fi
            if [[ "${enabled}" == "# S2S-ENABLED: no" ]]; then
                [[ "${raw}" == "# S2S-DISABLED:"* ]] || { CRON_MALFORMED_COUNT=$((CRON_MALFORMED_COUNT + 1)); i=$((i + 4)); continue; }
                candidate="${raw#\# S2S-DISABLED: }"
            else
                candidate="${raw}"
            fi
            if ! cron_parse_entry "${candidate}" "${system_format}"; then
                CRON_MALFORMED_COUNT=$((CRON_MALFORMED_COUNT + 1)); i=$((i + 4)); continue
            fi
            schedule="${CRON_PARSED_SCHEDULE}"; command="${CRON_PARSED_COMMAND}"
            job_user="${CRON_PARSED_USER:-${source_user}}"
            cron_add_inventory_job "${source}" "${source_label}" "${hash}" "${i}" "$((i + 3))" yes \
                "$([[ "${enabled}" == *yes ]] && echo ENABLED || echo DISABLED)" "${job_name:-Unnamed managed job}" \
                "${schedule}" "${job_user}" "${command}" "${candidate}"
            if [[ "${readable#\# S2S-READABLE: }" == "$(cron_schedule_readable "${schedule}")" ]]; then
                CRON_JOB_READABLE_MATCH[${CRON_JOB_COUNT}]=yes
            else
                CRON_JOB_READABLE_MATCH[${CRON_JOB_COUNT}]=no
            fi
            i=$((i + 4)); continue
        fi
        if [[ "${line}" == "# S2S-"* ]]; then
            case "${line}" in
                "${CRON_HEADER_MARKER}"|'# S2S MANAGER CRON INTEGRATION') ;;
                *) CRON_MALFORMED_COUNT=$((CRON_MALFORMED_COUNT + 1)) ;;
            esac
            i=$((i + 1)); continue
        fi
        if cron_parse_entry "${line}" "${system_format}"; then
            schedule="${CRON_PARSED_SCHEDULE}"; command="${CRON_PARSED_COMMAND}"
            job_user="${CRON_PARSED_USER:-${source_user}}"
            cron_add_inventory_job "${source}" "${source_label}" "${hash}" "${i}" "${i}" no ENABLED \
                "${command:0:42}" "${schedule}" "${job_user}" "${command}" "${line}"
            CRON_JOB_READABLE_MATCH[${CRON_JOB_COUNT}]=na
        elif [[ "${line}" =~ ^[[:space:]]*#[[:space:]]+(.+)$ ]]; then
            candidate="${BASH_REMATCH[1]}"
            if [[ "${candidate}" != S2S-* ]] && ! cron_is_documentation_example "${candidate}" && \
               cron_parse_entry "${candidate}" "${system_format}"; then
                schedule="${CRON_PARSED_SCHEDULE}"; command="${CRON_PARSED_COMMAND}"
                job_user="${CRON_PARSED_USER:-${source_user}}"
                cron_add_inventory_job "${source}" "${source_label}" "${hash}" "${i}" "${i}" possible DISABLED \
                    "${command:0:42}" "${schedule}" "${job_user}" "${command}" "${candidate}"
                CRON_JOB_READABLE_MATCH[${CRON_JOB_COUNT}]=na
            fi
        fi
        i=$((i + 1))
    done
    if (( CRON_MALFORMED_COUNT > malformed_before )); then
        CRON_MALFORMED_SOURCE_LIST+="|${source}|"
    fi
}

cron_build_inventory() {
    local source temp hash
    CRON_JOB_COUNT=0; CRON_MALFORMED_COUNT=0; CRON_SOURCE_ERROR_COUNT=0
    CRON_JOB_SOURCE=(); CRON_JOB_SOURCE_LABEL=(); CRON_JOB_SOURCE_HASH=()
    CRON_JOB_START=(); CRON_JOB_END=(); CRON_JOB_MANAGED=(); CRON_JOB_STATUS=()
    CRON_JOB_NAME=(); CRON_JOB_SCHEDULE=(); CRON_JOB_USER=(); CRON_JOB_COMMAND=(); CRON_JOB_RAW=(); CRON_JOB_READABLE_MATCH=()
    CRON_MALFORMED_SOURCE_LIST=""
    while IFS= read -r source; do
        [[ -n "${source}" ]] || continue
        temp="$(mktemp)" || return 1
        if cron_read_source_to_file "${source}" "${temp}"; then
            hash="$(cron_file_hash "${temp}")"
            cron_inventory_source "${source}" "${temp}" "${hash}"
        else
            CRON_SOURCE_ERROR_COUNT=$((CRON_SOURCE_ERROR_COUNT + 1))
        fi
        rm -f -- "${temp}"
    done < <(cron_list_sources)
}

cron_print_inventory() {
    local human="${1:-1}" i type_label readable display_name status_display type_display
    if (( CRON_JOB_COUNT == 0 )); then info "No regular cron jobs were found."; return; fi
    printf '%-4s %-10s %-10s %-16s %-18s %s\n' "#" "Status" "Type" "User" "Schedule" "Name"
    printf '%-4s %-10s %-10s %-16s %-18s %s\n' "────" "──────────" "──────────" "────────────────" "──────────────────" "────────────────────────────────────────"
    for ((i=1; i<=CRON_JOB_COUNT; i++)); do
        case "${CRON_JOB_MANAGED[$i]}" in
            yes) type_label="S2S"; type_display="${C_BOLD}${C_CYAN}${type_label}${C_RESET}"; display_name="${CRON_JOB_NAME[$i]}" ;;
            possible) type_label="POSSIBLE"; type_display="${C_BOLD}${C_YELLOW}${type_label}${C_RESET}"; display_name="" ;;
            *) type_label="EXTERNAL"; type_display="${C_DIM}${type_label}${C_RESET}"; display_name="" ;;
        esac
        if [[ "${CRON_JOB_STATUS[$i]}" == "ENABLED" ]]; then
            status_display="${C_BOLD}${C_GREEN}ENABLED${C_RESET}"
        else
            status_display="${C_BOLD}${C_YELLOW}DISABLED${C_RESET}"
        fi
        printf '%-4s ' "${i}"
        pad_ansi_right "${status_display}" 10
        printf ' '
        pad_ansi_right "${type_display}" 10
        printf ' %-16s %-18s %s\n' "${CRON_JOB_USER[$i]}" "${CRON_JOB_SCHEDULE[$i]}" "${display_name}"
        if [[ "${human}" == "1" ]]; then
            readable="$(cron_schedule_readable "${CRON_JOB_SCHEDULE[$i]}")"
            printf '     %-12s %s\n' "Readable:" "${readable}"
        fi
        printf '     %-12s %s\n' "Source:" "${CRON_JOB_SOURCE_LABEL[$i]}"
        printf '     %-12s %b%s%b\n' "Command:" "${C_BOLD}${C_CYAN}" "${CRON_JOB_COMMAND[$i]}" "${C_RESET}"
        if [[ "${CRON_JOB_READABLE_MATCH[$i]:-na}" == "no" ]]; then
            warn "Stored S2S-READABLE differs from the calculated schedule; editing or toggling regenerates it."
        fi
        if (( i < CRON_JOB_COUNT )); then
            printf '%b     ' "${C_DIM}"
            table_divider_segment 110
            printf '%b\n' "${C_RESET}"
        fi
    done
    if (( CRON_MALFORMED_COUNT > 0 )); then
        echo; warn "${CRON_MALFORMED_COUNT} malformed or isolated S2S metadata line(s) were detected. Writing is blocked for affected selections."
    fi
    (( CRON_SOURCE_ERROR_COUNT == 0 )) || warn "${CRON_SOURCE_ERROR_COUNT} cron source(s) could not be read and were not included."
}

cron_header_text() {
    cat <<'EOF'
# ==============================================================================
# S2S-MANAGER-CRON-FILE: 1
# S2S MANAGER CRON INTEGRATION
#
# This crontab may contain metadata blocks managed by S2S Manager.
# Manual jobs, variables and comments are allowed outside those blocks.
# Do not change, reorder or separate lines beginning with "# S2S-" in a block.
# Manual format changes inside a block may prevent correct detection.
# ==============================================================================
EOF
}

cron_prepare_header() {
    local file="$1" exact similar temp
    exact="$(grep -Fxc "${CRON_HEADER_MARKER}" "${file}" 2>/dev/null || true)"
    similar="$(grep -Fc 'S2S-MANAGER-CRON-FILE:' "${file}" 2>/dev/null || true)"
    if [[ "${exact}" == "1" && "${similar}" == "1" ]]; then return 0; fi
    if [[ "${exact}" != "0" || "${similar}" != "0" ]]; then
        error "The cron source contains a duplicated, unsupported or damaged S2S file marker."
        return 1
    fi
    temp="$(mktemp)" || return 1
    { cron_header_text; echo; cat "${file}"; } > "${temp}"
    mv -- "${temp}" "${file}"
}

cron_backup_source() {
    local source="$1" current="$2" safe timestamp backup
    mkdir -p "${CRON_BACKUP_DIR}"
    safe="$(cron_source_label "${source}" | tr '/ :' '___')"
    timestamp="$(date +%Y%m%d-%H%M%S)-$$-${RANDOM}"
    backup="${CRON_BACKUP_DIR}/${safe}-${timestamp}.bak"
    cp -- "${current}" "${backup}" || return 1
    chmod 600 "${backup}"
    printf '%s' "${backup}"
}

cron_install_source_file() {
    local source="$1" staged="$2" user path
    case "${source}" in
        user:*) user="${source#user:}"; crontab -u "${user}" "${staged}" ;;
        file:*) path="${source#file:}"; cp -- "${staged}" "${path}" ;;
        *) return 1 ;;
    esac
}

cron_write_staged_source() {
    local source="$1" expected_hash="$2" staged="$3" current backup current_hash
    current="$(mktemp)" || return 1
    if [[ "${CRON_MALFORMED_SOURCE_LIST}" == *"|${source}|"* ]]; then
        error "This cron source contains malformed S2S metadata. No changes were written."
        info "Review the affected S2S lines or restore a backup before changing this source."
        rm -f -- "${current}"
        return 1
    fi
    cron_read_source_to_file "${source}" "${current}" || { rm -f -- "${current}"; return 1; }
    current_hash="$(cron_file_hash "${current}")"
    if [[ "${current_hash}" != "${expected_hash}" ]]; then
        rm -f -- "${current}"
        error "The cron source changed outside S2S Manager. No changes were written."
        info "Reload the job list and repeat the operation."
        return 1
    fi
    cron_prepare_header "${staged}" || { rm -f -- "${current}"; return 1; }
    backup="$(cron_backup_source "${source}" "${current}")" || { rm -f -- "${current}"; return 1; }
    if cron_install_source_file "${source}" "${staged}"; then
        CRON_LAST_BACKUP="${backup}"
        rm -f -- "${current}"
        return 0
    fi
    warn "Writing failed. Attempting to restore the original source."
    cron_install_source_file "${source}" "${current}" >/dev/null 2>&1 || error "Automatic rollback failed; restore ${backup} manually."
    rm -f -- "${current}"
    return 1
}

cron_render_block() {
    local name="$1" status="$2" schedule="$3" user="$4" command="$5" system_format="$6" entry
    if [[ "${system_format}" == "1" ]]; then entry="${schedule} ${user} ${command}"; else entry="${schedule} ${command}"; fi
    printf '# S2S-JOB: %s\n' "${name}"
    printf '# S2S-ENABLED: %s\n' "$([[ "${status}" == "ENABLED" ]] && echo yes || echo no)"
    printf '# S2S-READABLE: %s\n' "$(cron_schedule_readable "${schedule}")"
    if [[ "${status}" == "ENABLED" ]]; then printf '%s\n' "${entry}"; else printf '# S2S-DISABLED: %s\n' "${entry}"; fi
}

cron_replace_lines() {
    local source="$1" expected="$2" start="$3" end="$4" replacement="$5"
    local current staged
    current="$(mktemp)" || return 1; staged="$(mktemp)" || { rm -f -- "${current}"; return 1; }
    cron_read_source_to_file "${source}" "${current}" || { rm -f -- "${current}" "${staged}"; return 1; }
    awk -v first="${start}" -v last="${end}" -v repl="${replacement}" '
        NR==first { while ((getline line < repl)>0) print line }
        NR<first || NR>last { print }
    ' "${current}" > "${staged}"
    cron_write_staged_source "${source}" "${expected}" "${staged}"
    local rc=$?; rm -f -- "${current}" "${staged}"; return "${rc}"
}

cron_append_block() {
    local source="$1" expected="$2" block="$3" current staged
    current="$(mktemp)" || return 1; staged="$(mktemp)" || { rm -f -- "${current}"; return 1; }
    cron_read_source_to_file "${source}" "${current}" || { rm -f -- "${current}" "${staged}"; return 1; }
    cp -- "${current}" "${staged}"
    [[ ! -s "${staged}" ]] || echo >> "${staged}"
    cat "${block}" >> "${staged}"
    cron_write_staged_source "${source}" "${expected}" "${staged}"
    local rc=$?; rm -f -- "${current}" "${staged}"; return "${rc}"
}

cron_select_job() {
    local mode="$1" i choice shown=0
    cron_build_inventory || return 1
    echo
    for ((i=1; i<=CRON_JOB_COUNT; i++)); do
        case "${mode}:${CRON_JOB_MANAGED[$i]}" in
            managed:yes|unmanaged:no|unmanaged:possible|all:*) ;;
            *) continue ;;
        esac
        printf '  [%d] %-10s %-14s %-18s %s\n' "${i}" "${CRON_JOB_STATUS[$i]}" "${CRON_JOB_USER[$i]}" \
            "${CRON_JOB_SCHEDULE[$i]}" "${CRON_JOB_NAME[$i]}"
        printf '      Source: %s\n' "${CRON_JOB_SOURCE_LABEL[$i]}"
        shown=$((shown + 1))
    done
    (( shown > 0 )) || { info "No matching cron jobs were found."; return 1; }
    echo; echo "B = Back    E = Exit"; echo
    read -r -p "Job number: " choice
    case "${choice}" in b|B|0|"") return 1 ;; e|E) clear_screen; echo "Bye."; exit 0 ;; esac
    [[ "${choice}" =~ ^[0-9]+$ ]] || return 1
    (( choice >= 1 && choice <= CRON_JOB_COUNT )) || return 1
    case "${mode}:${CRON_JOB_MANAGED[$choice]}" in managed:yes|unmanaged:no|unmanaged:possible|all:*) ;; *) return 1 ;; esac
    CRON_SELECTED="${choice}"
}

cron_prompt_name() {
    local default="${1:-}" value
    echo "Enter a short descriptive name. It is stored only as a normal # S2S-JOB comment."
    echo "B = back to Cron management    E = exit"
    while :; do
        read -r -p "Job name${default:+ [${default}]}: " value
        case "${value}" in b|B) return 1 ;; e|E) clear_screen; echo "Bye."; exit 0 ;; esac
        value="${value:-${default}}"
        if [[ -n "${value}" && "${value}" =~ [^[:space:]] && ${#value} -le 64 && "${value}" != *$'\n'* && "${value}" != *$'\r'* && "${value}" != *$'\t'* ]]; then CRON_PROMPT_NAME="${value}"; return 0; fi
        error "Enter a name from 1 through 64 characters."
    done
}

cron_prompt_navigation() {
    case "$1" in
        b|B) return 0 ;;
        e|E) clear_screen; echo "Bye."; exit 0 ;;
        *) return 1 ;;
    esac
}

cron_validate_schedule() {
    local value="$1" f1 f2 f3 f4 f5 extra
    if [[ "${value}" == @* ]]; then
        read -r f1 extra <<< "${value}"
        [[ -z "${extra}" ]] || return 1
    else
        read -r f1 f2 f3 f4 f5 extra <<< "${value}"
        [[ -n "${f5}" && -z "${extra}" ]] || return 1
    fi
    cron_parse_entry "${value} /bin/true" 0
}

cron_prompt_schedule() {
    local default="${1:-}" choice value minutes minute hour day weekdays
    while :; do
        echo
        echo "Choose when the command should run:"
        echo "  [1] Every X minutes"
        echo "  [2] Every hour"
        echo "  [3] Every day at a selected time"
        echo "  [4] Selected weekdays at a selected time"
        echo "  [5] Monthly"
        echo "  [6] At system startup"
        echo "  [7] Custom cron expression"
        [[ -n "${default}" ]] && echo "  [K] Keep current schedule: ${default}"
        echo "  [B] Back    [E] Exit"
        read -r -p "Schedule type: " choice
        case "${choice}" in
            1) read -r -p "Interval in minutes (1-59): " minutes; cron_prompt_navigation "${minutes}" && return 1; [[ "${minutes}" =~ ^[0-9]+$ ]] && (( minutes >= 1 && minutes <= 59 )) || { error "Enter 1 through 59."; continue; }; value="*/${minutes} * * * *" ;;
            2) read -r -p "Minute within each hour (0-59) [0]: " minute; cron_prompt_navigation "${minute}" && return 1; minute="${minute:-0}"; [[ "${minute}" =~ ^[0-9]+$ ]] && (( minute <= 59 )) || { error "Enter 0 through 59."; continue; }; value="$((10#${minute})) * * * *" ;;
            3) read -r -p "Time (HH:MM): " value; cron_prompt_navigation "${value}" && return 1; [[ "${value}" =~ ^([01]?[0-9]|2[0-3]):([0-5][0-9])$ ]] || { error "Enter a valid 24-hour time."; continue; }; hour="${value%:*}"; minute="${value#*:}"; value="$((10#${minute})) $((10#${hour})) * * *" ;;
            4)
                echo
                echo "Choose one or more weekdays. Sunday may be entered as 0 or 7; both"
                echo "mean the same day. Numbers and the following English names are accepted:"
                echo
                printf '  %-3s %-4s %-10s %s\n' "1" "MON" "MONDAY" "Monday"
                printf '  %-3s %-4s %-10s %s\n' "2" "TUE" "TUESDAY" "Tuesday"
                printf '  %-3s %-4s %-10s %s\n' "3" "WED" "WEDNESDAY" "Wednesday"
                printf '  %-3s %-4s %-10s %s\n' "4" "THU" "THURSDAY" "Thursday"
                printf '  %-3s %-4s %-10s %s\n' "5" "FRI" "FRIDAY" "Friday"
                printf '  %-3s %-4s %-10s %s\n' "6" "SAT" "SATURDAY" "Saturday"
                printf '  %-3s %-4s %-10s %s\n' "0/7" "SUN" "SUNDAY" "Sunday"
                echo "  Upper/lower case is ignored."
                echo
                echo "Separate individual days with commas; spaces and duplicates are cleaned up."
                echo "Ranges are allowed with a hyphen. Examples: 1,3,5   MON-FRI   Tue, Friday, 7"
                while :; do
                    read -r -p "Weekdays: " weekdays
                    cron_prompt_navigation "${weekdays}" && return 1
                    if cron_normalize_weekdays "${weekdays}"; then weekdays="${CRON_NORMALIZED_WEEKDAYS}"; break; fi
                    error "Invalid weekdays. Use only the displayed values, comma lists or ascending ranges such as MON-FRI."
                done
                printf '%-24s %s\n' "Normalized weekdays:" "${weekdays}"
                read -r -p "Time (HH:MM): " value; cron_prompt_navigation "${value}" && return 1
                [[ "${value}" =~ ^([01]?[0-9]|2[0-3]):([0-5][0-9])$ ]] || { error "Enter a valid time."; continue; }
                hour="${value%:*}"; minute="${value#*:}"; value="$((10#${minute})) $((10#${hour})) * * ${weekdays}"
                ;;
            5) read -r -p "Day of month (1-31): " day; cron_prompt_navigation "${day}" && return 1; [[ "${day}" =~ ^[0-9]+$ ]] && (( day >= 1 && day <= 31 )) || { error "Enter 1 through 31."; continue; }; read -r -p "Time (HH:MM): " value; cron_prompt_navigation "${value}" && return 1; [[ "${value}" =~ ^([01]?[0-9]|2[0-3]):([0-5][0-9])$ ]] || { error "Enter a valid time."; continue; }; hour="${value%:*}"; minute="${value#*:}"; value="$((10#${minute})) $((10#${hour})) ${day} * *" ;;
            6) value="@reboot" ;;
            7) echo "Enter five cron fields, for example: 30 3 * * *"; read -r -p "Cron expression: " value; cron_prompt_navigation "${value}" && return 1; cron_validate_schedule "${value}" || { error "The cron expression is not valid or supported."; continue; } ;;
            k|K) [[ -n "${default}" ]] || { error "There is no current schedule."; continue; }; value="${default}" ;;
            b|B|0|"") return 1 ;;
            e|E) clear_screen; echo "Bye."; exit 0 ;;
            *) error "Invalid selection."; continue ;;
        esac
        CRON_PROMPT_SCHEDULE="${value}"
        CRON_PROMPT_READABLE="$(cron_schedule_readable "${value}")"
        printf '%-24s %s\n' "Cron expression:" "${value}"
        printf '%-24s %s\n' "Human readable:" "${CRON_PROMPT_READABLE}"
        return 0
    done
}

cron_prompt_command() {
    local default="${1:-}" value choice logfile
    echo
    echo "Enter an existing executable script path or an advanced shell command."
    echo "URLs are not commands by themselves. Pipes, redirects, quotes and '%' have"
    echo "normal cron/shell meaning; review the exact preview carefully."
    while :; do
        read -r -p "Command${default:+ [keep current with ENTER]}: " value
        case "${value}" in b|B) return 1 ;; e|E) clear_screen; echo "Bye."; exit 0 ;; esac
        value="${value:-${default}}"
        [[ -n "${value}" && "${value}" != *$'\n'* && "${value}" != *$'\r'* ]] && break
        error "Command must not be empty or contain a newline. Please try again."
    done
    if [[ -z "${default}" ]]; then
        echo; echo "Logging:"; echo "  [1] Keep command output handled by cron"; echo "  [2] Append stdout and stderr to a log file"; echo "  [3] Discard stdout and stderr"
        while :; do
            read -r -p "Logging [1]: " choice
            cron_prompt_navigation "${choice}" && return 1
            case "${choice:-1}" in
                1) break ;;
                2)
                    while :; do
                        read -r -p "Absolute log file path (no spaces): " logfile
                        cron_prompt_navigation "${logfile}" && return 1
                        [[ "${logfile}" =~ ^/[A-Za-z0-9._/-]+$ ]] && break
                        error "Enter a safe absolute log path without spaces."
                    done
                    value="${value} >> ${logfile} 2>&1"; break
                    ;;
                3) value="${value} >/dev/null 2>&1"; break ;;
                *) error "Invalid logging selection. Please try again." ;;
            esac
        done
    fi
    CRON_PROMPT_COMMAND="${value}"
}

cron_prompt_user() {
    local default="${1:-root}" user
    while :; do
        read -r -p "Run as existing user [${default}]: " user
        cron_prompt_navigation "${user}" && return 1
        user="${user:-${default}}"
        if id "${user}" >/dev/null 2>&1; then CRON_PROMPT_USER="${user}"; return 0; fi
        error "User '${user}' does not exist. Please try again."
    done
}

cron_prompt_initial_status() {
    local answer
    while :; do
        echo; echo "Initial status:"; echo "  [1] Enabled"; echo "  [2] Disabled"; echo "  [B] Back    [E] Exit"
        read -r -p "Status [1]: " answer
        cron_prompt_navigation "${answer}" && return 1
        case "${answer:-1}" in 1) CRON_PROMPT_STATUS="ENABLED"; return 0 ;; 2) CRON_PROMPT_STATUS="DISABLED"; return 0 ;; *) error "Invalid status selection." ;; esac
    done
}

cron_source_current_hash() {
    local source="$1" temp hash
    temp="$(mktemp)" || return 1
    cron_read_source_to_file "${source}" "${temp}" || { rm -f -- "${temp}"; return 1; }
    hash="$(cron_file_hash "${temp}")"; rm -f -- "${temp}"; printf '%s' "${hash}"
}

cron_add_job() {
    local user source expected block status
    banner; section "ADD CRON JOB"
    echo "Creates a normal job in a user's crontab. Root is the default because the"
    echo "S2S Manager itself runs as root. The selected user must already exist."
    echo "The complete source is backed up before writing."
    echo
    cron_command_available || { error "crontab is not installed."; pause; return; }
    cron_prompt_name || return
    cron_prompt_schedule || return
    cron_prompt_command || return
    cron_prompt_user root || return; user="${CRON_PROMPT_USER}"
    cron_prompt_initial_status || return; status="${CRON_PROMPT_STATUS}"
    cron_build_inventory || { error "Existing cron sources could not be checked safely."; pause; return; }
    source="user:${user}"; expected="$(cron_source_current_hash "${source}")" || { error "Could not read ${user}'s crontab."; pause; return; }
    block="$(mktemp)" || return; cron_render_block "${CRON_PROMPT_NAME}" "${status}" "${CRON_PROMPT_SCHEDULE}" "${user}" "${CRON_PROMPT_COMMAND}" 0 > "${block}"
    section "CRON JOB PREVIEW"
    printf '%-24s %s\n' "Name:" "${CRON_PROMPT_NAME}"; printf '%-24s %s\n' "User:" "${user}"
    printf '%-24s %s\n' "Schedule:" "${CRON_PROMPT_SCHEDULE}"; printf '%-24s %s\n' "Meaning:" "${CRON_PROMPT_READABLE}"
    printf '%-24s %s\n' "Command:" "${CRON_PROMPT_COMMAND}"; printf '%-24s %s\n' "Status:" "${status}"
    warn "This command will execute automatically with the permissions of ${user}."
    if confirm_yes_no "Create this cron job?" "N" && cron_append_block "${source}" "${expected}" "${block}"; then
        ok "Cron job created."; printf '%-24s %s\n' "Safety backup:" "${CRON_LAST_BACKUP}"
    else info "No cron job was created."; fi
    rm -f -- "${block}"; pause
}

cron_take_over_job() {
    local i source block system_format=0 name status
    banner; section "TAKE OVER EXISTING CRON JOB"
    cron_command_available || { error "Install cron before changing scheduled jobs."; pause; return; }
    cron_select_job unmanaged || { pause; return; }; i="${CRON_SELECTED}"
    source="${CRON_JOB_SOURCE[$i]}"; cron_source_is_system "${source}" && system_format=1
    cron_warn_package_owned_source "${source}"
    if [[ "${CRON_JOB_MANAGED[$i]}" == "possible" ]]; then
        warn "This line is currently only a comment. It may be an intentionally disabled job, an example or old documentation."
        echo "Taking it over classifies it as a real disabled cron job. No command is executed now."
        status="DISABLED"
    else status="ENABLED"; fi
    echo; printf '%-24s %s\n' "Source:" "${CRON_JOB_SOURCE_LABEL[$i]}"; printf '%-24s %s\n' "Schedule:" "${CRON_JOB_SCHEDULE[$i]}"
    printf '%-24s %s\n' "Meaning:" "$(cron_schedule_readable "${CRON_JOB_SCHEDULE[$i]}")"
    printf '%-24s %s\n' "User:" "${CRON_JOB_USER[$i]}"; printf '%-24s %s\n' "Command:" "${CRON_JOB_COMMAND[$i]}"; printf '%-24s %s\n' "Resulting status:" "${status}"
    cron_prompt_name "${CRON_JOB_NAME[$i]}" || return
    confirm_yes_no "Take over this existing cron entry?" "N" || return
    block="$(mktemp)" || return
    cron_render_block "${CRON_PROMPT_NAME}" "${status}" "${CRON_JOB_SCHEDULE[$i]}" "${CRON_JOB_USER[$i]}" "${CRON_JOB_COMMAND[$i]}" "${system_format}" > "${block}"
    if cron_replace_lines "${source}" "${CRON_JOB_SOURCE_HASH[$i]}" "${CRON_JOB_START[$i]}" "${CRON_JOB_END[$i]}" "${block}"; then
        ok "Cron job taken over without changing its schedule, user or command."; printf '%-24s %s\n' "Safety backup:" "${CRON_LAST_BACKUP}"
    fi
    rm -f -- "${block}"; pause
}

cron_edit_job() {
    local i source system_format=0 name schedule command user block
    banner; section "EDIT MANAGED CRON JOB"
    cron_command_available || { error "Install cron before changing scheduled jobs."; pause; return; }
    cron_select_job managed || { pause; return; }; i="${CRON_SELECTED}"; source="${CRON_JOB_SOURCE[$i]}"
    cron_warn_package_owned_source "${source}"
    cron_source_is_system "${source}" && system_format=1
    cron_prompt_name "${CRON_JOB_NAME[$i]}" || return; name="${CRON_PROMPT_NAME}"
    cron_prompt_schedule "${CRON_JOB_SCHEDULE[$i]}" || return; schedule="${CRON_PROMPT_SCHEDULE}"
    cron_prompt_command "${CRON_JOB_COMMAND[$i]}" || return; command="${CRON_PROMPT_COMMAND}"
    cron_prompt_user "${CRON_JOB_USER[$i]}" || return; user="${CRON_PROMPT_USER}"
    block="$(mktemp)" || return
    cron_render_block "${name}" "${CRON_JOB_STATUS[$i]}" "${schedule}" "${user}" "${command}" "${system_format}" > "${block}"
    section "EDIT PREVIEW"
    printf '%-24s %s\n' "Source:" "${CRON_JOB_SOURCE_LABEL[$i]}"
    if [[ "${system_format}" == "0" && "${user}" != "${CRON_JOB_USER[$i]}" ]]; then
        printf '%-24s %s crontab -> %s crontab\n' "User/source move:" "${CRON_JOB_USER[$i]}" "${user}"
    fi
    cat "${block}"; echo
    if ! confirm_yes_no "Apply these changes?" "N"; then rm -f -- "${block}"; return; fi
    if [[ "${system_format}" == "0" && "${user}" != "${CRON_JOB_USER[$i]}" ]]; then
        if cron_move_user_job "${i}" "${user}" "${block}"; then
            ok "Cron job moved to ${user}'s crontab and updated."
        fi
    elif cron_replace_lines "${source}" "${CRON_JOB_SOURCE_HASH[$i]}" "${CRON_JOB_START[$i]}" "${CRON_JOB_END[$i]}" "${block}"; then
        ok "Cron job updated."; printf '%-24s %s\n' "Safety backup:" "${CRON_LAST_BACKUP}"
    fi
    rm -f -- "${block}"; pause
}

cron_toggle_job() {
    local i source system_format=0 new_status block
    banner; section "ENABLE / DISABLE MANAGED CRON JOB"
    cron_command_available || { error "Install cron before changing scheduled jobs."; pause; return; }
    cron_select_job managed || { pause; return; }; i="${CRON_SELECTED}"; source="${CRON_JOB_SOURCE[$i]}"
    cron_warn_package_owned_source "${source}"
    cron_source_is_system "${source}" && system_format=1
    [[ "${CRON_JOB_STATUS[$i]}" == "ENABLED" ]] && new_status="DISABLED" || new_status="ENABLED"
    printf '%-24s %s\n' "Job:" "${CRON_JOB_NAME[$i]}"; printf '%-24s %s -> %s\n' "Status:" "${CRON_JOB_STATUS[$i]}" "${new_status}"
    printf '%-24s %s\n' "Schedule:" "${CRON_JOB_SCHEDULE[$i]}"; printf '%-24s %s\n' "Command:" "${CRON_JOB_COMMAND[$i]}"
    confirm_yes_no "Change this job's status?" "N" || return
    block="$(mktemp)" || return
    cron_render_block "${CRON_JOB_NAME[$i]}" "${new_status}" "${CRON_JOB_SCHEDULE[$i]}" "${CRON_JOB_USER[$i]}" "${CRON_JOB_COMMAND[$i]}" "${system_format}" > "${block}"
    if cron_replace_lines "${source}" "${CRON_JOB_SOURCE_HASH[$i]}" "${CRON_JOB_START[$i]}" "${CRON_JOB_END[$i]}" "${block}"; then
        ok "Cron job is now ${new_status}."; printf '%-24s %s\n' "Safety backup:" "${CRON_LAST_BACKUP}"
    fi
    rm -f -- "${block}"; pause
}

cron_run_job_now() {
    local i command user started ended rc answer
    banner; section "RUN MANAGED CRON JOB NOW"
    cron_command_available || { error "Install cron before running managed jobs."; pause; return; }
    cron_select_job managed || { pause; return; }; i="${CRON_SELECTED}"; command="${CRON_JOB_COMMAND[$i]}"; user="${CRON_JOB_USER[$i]}"
    printf '%-24s %s\n' "Job:" "${CRON_JOB_NAME[$i]}"; printf '%-24s %s\n' "Run as:" "${user}"; printf '%-24s %s\n' "Command:" "${command}"
    warn "This is a real execution, not a simulation. Cron-specific environment variables are not reproduced."
    if grep -Eq '(^|[^\\])%' <<< "${command}"; then error "The command contains an unescaped %. Manual execution could differ from cron and is refused."; pause; return; fi
    read -r -p "Type RUN to execute now: " answer; [[ "${answer}" == "RUN" ]] || return
    started="$(date +%s)"; echo; section "COMMAND OUTPUT"
    if [[ "${user}" == "root" ]]; then /bin/sh -c "${command}"; rc=$?; else runuser -u "${user}" -- /bin/sh -c "${command}"; rc=$?; fi
    ended="$(date +%s)"; echo; section "EXECUTION RESULT"; printf '%-24s %s\n' "Exit code:" "${rc}"; printf '%-24s %s seconds\n' "Runtime:" "$((ended - started))"
    (( rc == 0 )) && ok "Manual execution completed successfully." || error "Manual execution failed."
    pause
}

cron_delete_job() {
    local i empty answer
    banner; section "DELETE MANAGED CRON JOB"
    cron_command_available || { error "Install cron before changing scheduled jobs."; pause; return; }
    cron_select_job managed || { pause; return; }; i="${CRON_SELECTED}"
    cron_warn_package_owned_source "${CRON_JOB_SOURCE[$i]}"
    printf '%-24s %s\n' "Job:" "${CRON_JOB_NAME[$i]}"; printf '%-24s %s\n' "Source:" "${CRON_JOB_SOURCE_LABEL[$i]}"; printf '%-24s %s\n' "Command:" "${CRON_JOB_COMMAND[$i]}"
    warn "Deleting this block permanently stops future scheduled executions. A source backup is created first."
    read -r -p "Type DELETE to remove this complete S2S block: " answer; [[ "${answer}" == "DELETE" ]] || return
    empty="$(mktemp)" || return
    if cron_replace_lines "${CRON_JOB_SOURCE[$i]}" "${CRON_JOB_SOURCE_HASH[$i]}" "${CRON_JOB_START[$i]}" "${CRON_JOB_END[$i]}" "${empty}"; then
        ok "Cron job deleted."; printf '%-24s %s\n' "Safety backup:" "${CRON_LAST_BACKUP}"
    fi
    rm -f -- "${empty}"; pause
}

cron_show_overview() {
    banner; section "ALL CRON JOBS"
    info "Reading user crontabs, /etc/crontab and /etc/cron.d. This can take a few seconds..."; echo
    cron_build_inventory || { error "Cron sources could not be read."; pause; return; }
    cron_print_inventory "${CRON_HUMAN_READABLE}"
    cron_show_periodic_directories
    echo; info "S2S = managed job; EXTERNAL = active job outside manager control; POSSIBLE = plausible commented job."
    pause
}

cron_show_periodic_directories() {
    local directory file found=0
    section "PERIODIC SCRIPT DIRECTORIES"
    echo "These entries are executable scripts selected by directory, not ordinary"
    echo "five-field cron lines. They are displayed here but not edited as job lines."
    echo
    for directory in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
        [[ -d "${directory}" ]] || continue
        for file in "${directory}"/*; do
            [[ -f "${file}" ]] || continue
            printf '%-24s %-10s %s\n' "${directory}" "$([[ -x "${file}" ]] && echo executable || echo disabled)" "$(basename "${file}")"
            found=$((found + 1))
        done
    done
    (( found > 0 )) || info "No periodic directory scripts were found."
}

cron_move_user_job() {
    local index="$1" new_user="$2" block="$3" old_source target_source old_current old_staged target_current target_staged
    local target_hash target_backup old_backup current_hash
    old_source="${CRON_JOB_SOURCE[$index]}"; target_source="user:${new_user}"
    if [[ "${CRON_MALFORMED_SOURCE_LIST}" == *"|${old_source}|"* || "${CRON_MALFORMED_SOURCE_LIST}" == *"|${target_source}|"* ]]; then
        error "The original or target crontab contains malformed S2S metadata. No changes were written."
        return 1
    fi
    old_current="$(mktemp)" || return 1; old_staged="$(mktemp)" || { rm -f -- "${old_current}"; return 1; }
    target_current="$(mktemp)" || { rm -f -- "${old_current}" "${old_staged}"; return 1; }
    target_staged="$(mktemp)" || { rm -f -- "${old_current}" "${old_staged}" "${target_current}"; return 1; }

    cron_read_source_to_file "${old_source}" "${old_current}" || return 1
    current_hash="$(cron_file_hash "${old_current}")"
    if [[ "${current_hash}" != "${CRON_JOB_SOURCE_HASH[$index]}" ]]; then
        error "The original crontab changed outside S2S Manager. No changes were written."
        rm -f -- "${old_current}" "${old_staged}" "${target_current}" "${target_staged}"; return 1
    fi
    cron_read_source_to_file "${target_source}" "${target_current}" || return 1
    target_hash="$(cron_file_hash "${target_current}")"
    cp -- "${target_current}" "${target_staged}"; [[ ! -s "${target_staged}" ]] || echo >> "${target_staged}"; cat "${block}" >> "${target_staged}"
    awk -v first="${CRON_JOB_START[$index]}" -v last="${CRON_JOB_END[$index]}" 'NR<first || NR>last {print}' "${old_current}" > "${old_staged}"
    cron_prepare_header "${target_staged}" && cron_prepare_header "${old_staged}" || { rm -f -- "${old_current}" "${old_staged}" "${target_current}" "${target_staged}"; return 1; }

    if [[ "$(cron_source_current_hash "${target_source}")" != "${target_hash}" ]] || \
       [[ "$(cron_source_current_hash "${old_source}")" != "${CRON_JOB_SOURCE_HASH[$index]}" ]]; then
        error "A source crontab changed outside S2S Manager. No changes were written."
        rm -f -- "${old_current}" "${old_staged}" "${target_current}" "${target_staged}"; return 1
    fi
    target_backup="$(cron_backup_source "${target_source}" "${target_current}")" || return 1
    old_backup="$(cron_backup_source "${old_source}" "${old_current}")" || return 1
    if ! cron_install_source_file "${target_source}" "${target_staged}"; then
        error "The target user's crontab could not be written. Nothing was moved."
        rm -f -- "${old_current}" "${old_staged}" "${target_current}" "${target_staged}"; return 1
    fi
    if ! cron_install_source_file "${old_source}" "${old_staged}"; then
        error "Removing the original failed; restoring the target user's crontab."
        cron_install_source_file "${target_source}" "${target_current}" >/dev/null 2>&1 || error "Target rollback failed; restore ${target_backup} manually."
        rm -f -- "${old_current}" "${old_staged}" "${target_current}" "${target_staged}"; return 1
    fi
    printf '%-24s %s\n' "Original backup:" "${old_backup}"
    printf '%-24s %s\n' "Target backup:" "${target_backup}"
    rm -f -- "${old_current}" "${old_staged}" "${target_current}" "${target_staged}"
}

cron_warn_package_owned_source() {
    local source="$1" path owner
    [[ "${source}" == file:* ]] || return 0
    path="${source#file:}"
    if command_available dpkg-query; then
        owner="$(dpkg-query -S "${path}" 2>/dev/null | head -1 || true)"
        if [[ -n "${owner}" ]]; then
            warn "This cron source belongs to a Debian package: ${owner%%:*}"
            echo "A future package update may replace or conflict with manual changes."
        fi
    fi
}

cron_install_package() {
    local answer
    banner; section "INSTALL CRON SERVICE"
    if cron_command_available; then info "The crontab command is already installed."; pause; return; fi
    warn "This installs the Debian cron package and starts/enables cron.service."
    echo "Existing system files are not removed. New scheduled jobs can execute automatically"
    echo "with their configured user's permissions after they are enabled."
    read -r -p "Type INSTALL CRON to continue: " answer
    [[ "${answer}" == "INSTALL CRON" ]] || return
    apt-get update && apt-get install -y cron || { error "Cron package installation failed."; pause; return; }
    systemctl enable --now cron || { error "cron.service could not be enabled and started."; pause; return; }
    ok "Cron installed, active and enabled at boot."
    pause
}

cron_diagnostics() {
    local active enabled i source path owner mode command_path
    banner; section "CRON SERVICE AND DIAGNOSTICS"
    cron_command_available && ok "crontab command available." || error "crontab is not installed."
    if systemctl is-active --quiet cron 2>/dev/null; then active="active"; ok "cron.service is active."; else active="inactive"; error "cron.service is not active."; fi
    if systemctl is-enabled --quiet cron 2>/dev/null; then enabled="enabled"; ok "cron.service is enabled at boot."; else enabled="disabled"; warn "cron.service is not enabled at boot."; fi
    cron_build_inventory || true
    printf '%-24s %s\n' "Detected jobs:" "${CRON_JOB_COUNT}"; printf '%-24s %s\n' "Unreadable sources:" "${CRON_SOURCE_ERROR_COUNT}"; printf '%-24s %s\n' "Malformed S2S metadata:" "${CRON_MALFORMED_COUNT}"
    (( CRON_MALFORMED_COUNT == 0 )) && ok "No malformed S2S cron metadata was detected." || error "Malformed S2S metadata requires manual review before that block is changed."
    section "JOB USERS AND COMMANDS"
    for ((i=1; i<=CRON_JOB_COUNT; i++)); do
        if id "${CRON_JOB_USER[$i]}" >/dev/null 2>&1; then
            ok "${CRON_JOB_NAME[$i]}: user ${CRON_JOB_USER[$i]} exists."
        else
            error "${CRON_JOB_NAME[$i]}: user ${CRON_JOB_USER[$i]} does not exist."
        fi
        command_path="${CRON_JOB_COMMAND[$i]%% *}"
        if [[ "${command_path}" == /* ]]; then
            if [[ -x "${command_path}" ]]; then
                ok "${CRON_JOB_NAME[$i]}: ${command_path} is executable."
            elif [[ -e "${command_path}" ]]; then
                warn "${CRON_JOB_NAME[$i]}: ${command_path} exists but is not executable."
            else
                warn "${CRON_JOB_NAME[$i]}: command path ${command_path} does not exist."
            fi
        fi
    done
    (( CRON_JOB_COUNT > 0 )) || info "No regular jobs were available for user/command checks."

    section "SYSTEM CRON FILE PERMISSIONS"
    while IFS= read -r source; do
        [[ "${source}" == file:* ]] || continue
        path="${source#file:}"
        owner="$(stat -c '%U:%G' "${path}" 2>/dev/null || echo unknown)"
        mode="$(stat -c '%a' "${path}" 2>/dev/null || echo unknown)"
        printf '%-34s owner=%-14s mode=%s\n' "${path}" "${owner}" "${mode}"
        [[ "${owner}" == "root:root" ]] || warn "${path} is not owned by root:root."
        if [[ "${mode}" =~ ^[0-7]*[2367][0-7]$ || "${mode}" =~ ^[0-7]*[0-7][2367]$ ]]; then
            error "${path} is writable by group or others."
        fi
    done < <(cron_list_sources)
    section "RECENT CRON JOURNAL"
    journalctl -u cron -n 30 --no-pager 2>/dev/null || info "No cron journal entries could be displayed."
    info "Diagnostics did not change the cron service or any job."
    pause
}

cron_management_menu() {
    local choice install_line
    while :; do
        install_line=""
        cron_command_available || install_line="  [9] Install cron package"
        banner; section "CRON / SCHEDULED TASKS"
        cat <<EOF
Manage regular user crontabs, /etc/crontab and existing /etc/cron.d files.
External lines are preserved. Every write creates a backup and checks that the
source has not changed since selection.

  [1] Show all cron jobs
  [2] Add cron job
  [3] Take over active or possible commented job
  [4] Edit managed cron job
  [5] Enable / disable managed cron job
  [6] Run managed cron job now
  [7] Delete managed cron job
  [8] Cron service and diagnostics
${install_line}
  [H] Human-readable schedule: $([[ "${CRON_HUMAN_READABLE}" == "1" ]] && echo ON || echo OFF)
  [B] Back to main menu
  [E] Exit
EOF
        echo; read -r -p "Selection: " choice
        case "${choice}" in
            1) cron_show_overview ;; 2) cron_add_job ;; 3) cron_take_over_job ;; 4) cron_edit_job ;;
            5) cron_toggle_job ;; 6) cron_run_job_now ;; 7) cron_delete_job ;; 8) cron_diagnostics ;; 9) cron_install_package ;;
            h|H) [[ "${CRON_HUMAN_READABLE}" == "1" ]] && CRON_HUMAN_READABLE=0 || CRON_HUMAN_READABLE=1 ;;
            b|B|0|"") return ;; e|E) clear_screen; echo "Bye."; exit 0 ;; *) error "Invalid selection."; sleep 1 ;;
        esac
    done
}

# End cron / scheduled-task management

# ==============================================================================
# Samba / file-share management
# ==============================================================================

samba_installed() {
    command_available smbd && command_available testparm
}

samba_service_active() {
    systemctl is-active --quiet smbd 2>/dev/null
}

valid_samba_share_name() {
    local value="$1"
    (( ${#value} >= 1 && ${#value} <= 64 )) || return 1
    [[ "${value}" =~ ^[A-Za-z0-9][A-Za-z0-9._\ -]*$ ]] || return 1
    case "${value,,}" in global|homes|printers|print\$|ipc\$) return 1 ;; esac
}

valid_samba_group_name() {
    [[ "$1" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]
}

valid_new_samba_path() {
    local value="$1"
    [[ "${value}" == /srv/* && "${value}" != *$'\n'* && "${value}" != *$'\r'* ]] || return 1
    [[ "${value}" =~ ^/srv/[A-Za-z0-9._/-]+$ ]] || return 1
    [[ "${value}" != *'/../'* && "${value}" != */.. && "${value}" != *'//'* ]]
}

samba_path_resolves_safely() {
    local value="$1" resolved
    resolved="$(readlink -m -- "${value}" 2>/dev/null)" || return 1
    [[ "${resolved}" == "${value}" && "${resolved}" == /srv/* ]]
}

samba_system_share() {
    case "${1,,}" in homes|printers|print\$|ipc\$) return 0 ;; *) return 1 ;; esac
}

samba_effective_config() {
    testparm -s "${SAMBA_CONFIG}" 2>/dev/null
}

samba_effective_share_names() {
    samba_effective_config | awk '/^\[[^]]+\]$/ { name=substr($0,2,length($0)-2); if (tolower(name)!="global") print name }'
}

samba_share_is_managed() {
    local name="$1"
    [[ -f "${SAMBA_SHARE_DIR}/${name}.share" ]] || return 1
    grep -Fqx "# S2S-SHARE: ${name}" "${SAMBA_MANAGER_CONFIG}" 2>/dev/null
}

samba_effective_share_block() {
    local wanted="$1"
    samba_effective_config | awk -v wanted="${wanted}" '
        /^\[[^]]+\]$/ {
            name=substr($0,2,length($0)-2)
            active=(tolower(name)==tolower(wanted))
        }
        active { print }
    '
}

samba_find_raw_share_source() {
    local wanted="$1" file count=0 found=""
    while IFS= read -r file; do
        if awk -v wanted="${wanted}" '
            /^\[[^]]+\][[:space:]]*$/ {
                name=$0; sub(/^[[:space:]]*\[/,"",name); sub(/\][[:space:]]*$/,"",name)
                if (tolower(name)==tolower(wanted)) found=1
            }
            END { exit(found ? 0 : 1) }
        ' "${file}"; then
            count=$((count + 1)); found="${file}"
        fi
    done < <(find /etc/samba -maxdepth 2 -type f \( -name '*.conf' -o -name 'smb.conf' \) 2>/dev/null | sort)
    (( count == 1 )) || return 1
    printf '%s' "${found}"
}

samba_backup_file() {
    local file="$1" label="$2" stamp target mode uid gid
    stamp="$(date +%Y%m%d-%H%M%S)-${RANDOM}"
    target="${SAMBA_BACKUP_DIR}/${label}-${stamp}.bak"
    if [[ -e "${file}" ]]; then
        mode="$(stat -c '%a' "${file}")"; uid="$(stat -c '%u' "${file}")"; gid="$(stat -c '%g' "${file}")"
        cp -a -- "${file}" "${target}"
        printf 'MODE=%s\nUID_VALUE=%s\nGID_VALUE=%s\n' "${mode}" "${uid}" "${gid}" > "${target}.meta"
        chmod 600 "${target}.meta"
    else : > "${target}.absent"; target="${target}.absent"; fi
    chmod 600 "${target}"
    printf '%s' "${target}"
}

samba_restore_backup() {
    local backup="$1" target="$2" mode uid gid
    [[ -f "${backup}" && -f "${backup}.meta" ]] || return 1
    mode="$(awk -F= '$1=="MODE" {print $2}' "${backup}.meta")"
    uid="$(awk -F= '$1=="UID_VALUE" {print $2}' "${backup}.meta")"
    gid="$(awk -F= '$1=="GID_VALUE" {print $2}' "${backup}.meta")"
    [[ "${mode}" =~ ^[0-7]{3,4}$ && "${uid}" =~ ^[0-9]+$ && "${gid}" =~ ^[0-9]+$ ]] || return 1
    install -m "${mode}" "${backup}" "${target}" && chown "${uid}:${gid}" "${target}"
}

samba_ensure_manager_include() {
    if awk -v wanted="${SAMBA_INCLUDE_LINE}" '
        /^\[[^]]+\][[:space:]]*$/ { section=tolower($0); in_global=(section=="[global]") }
        { line=$0; sub(/^[[:space:]]*/,"",line); sub(/[[:space:]]*$/,"",line); if (in_global && line==wanted) found=1 }
        END { exit(found ? 0 : 1) }
    ' "${SAMBA_CONFIG}"; then return 0; fi
    if grep -Fq "${SAMBA_INCLUDE_LINE}" "${SAMBA_CONFIG}" 2>/dev/null; then
        error "The manager include already exists outside [global]; refusing to create an ambiguous configuration."
        return 1
    fi
    local temp
    temp="$(mktemp "${SAMBA_CONFIG}.s2s.XXXXXX")" || return 1
    awk -v include_line="   ${SAMBA_INCLUDE_LINE}" '
        BEGIN { inserted=0; in_global=0 }
        /^\[global\][[:space:]]*$/ { in_global=1; print; next }
        /^\[[^]]+\][[:space:]]*$/ && in_global && !inserted { print include_line; print ""; inserted=1; in_global=0 }
        { print }
        END { if (!inserted && in_global) { print include_line } }
    ' "${SAMBA_CONFIG}" > "${temp}"
    if ! grep -Fq "${SAMBA_INCLUDE_LINE}" "${temp}"; then rm -f -- "${temp}"; return 1; fi
    install -m 0644 "${temp}" "${SAMBA_CONFIG}"
    rm -f -- "${temp}"
}

samba_write_managed_share() {
    local name="$1" path="$2" group="$3" state="${SAMBA_SHARE_DIR}/${name}.share"
    mkdir -p "${SAMBA_SHARE_DIR}"
    touch "${SAMBA_MANAGER_CONFIG}"
    chmod 0644 "${SAMBA_MANAGER_CONFIG}"
    cat >> "${SAMBA_MANAGER_CONFIG}" <<EOF

# S2S-SHARE: ${name}
[${name}]
   path = ${path}
   valid users = @${group}
   read only = no
   force group = ${group}
   create mask = 0660
   force create mode = 0660
   directory mask = 2770
   force directory mode = 2770
EOF
    printf 'NAME=%q\nPATH_VALUE=%q\nGROUP_VALUE=%q\n' "${name}" "${path}" "${group}" > "${state}"
    chmod 600 "${state}"
}

samba_write_imported_share() {
    local name="$1" effective="$2" path="$3" group="$4" state="${SAMBA_SHARE_DIR}/${name}.share"
    printf '\n# S2S-SHARE: %s\n%s\n' "${name}" "${effective}" >> "${SAMBA_MANAGER_CONFIG}"
    printf 'NAME=%q\nPATH_VALUE=%q\nGROUP_VALUE=%q\n' "${name}" "${path}" "${group}" > "${state}"
    chmod 600 "${state}"
}

samba_remove_share_block_from_file() {
    local file="$1" wanted="$2" temp file_mode
    temp="$(mktemp "${file}.s2s.XXXXXX")" || return 1
    awk -v wanted="${wanted}" '
        function header_name(line, name) { name=line; sub(/^[[:space:]]*\[/,"",name); sub(/\][[:space:]]*$/,"",name); return tolower(name) }
        /^# S2S-SHARE: / { pending=$0; next }
        /^\[[^]]+\][[:space:]]*$/ {
            target=(header_name($0)==tolower(wanted))
            if (!target && pending != "") print pending
            pending=""; skip=target
            if (!skip) print
            next
        }
        {
            if (pending != "") { print pending; pending="" }
            if (!skip) print
        }
        END { if (pending != "") print pending }
    ' "${file}" > "${temp}"
    file_mode="$(stat -c '%a' "${file}" 2>/dev/null || stat -f '%Lp' "${file}" 2>/dev/null || echo 644)"
    install -m "${file_mode}" "${temp}" "${file}"
    rm -f -- "${temp}"
}

samba_install() {
    banner; section "INSTALL SAMBA"
    samba_installed && { info "Samba is already installed."; pause; return; }
    echo "Installs the Debian samba package and enables/starts smbd."
    echo "No share, user, directory or firewall rule is created by this step."
    echo; warn "Package installation changes this Debian system."
    confirm_yes_no "Install Samba now?" "N" || return
    if apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y samba && systemctl enable --now smbd; then
        ok "Samba installed and smbd enabled at boot."
    else error "Samba installation or service activation failed."; fi
    pause
}

samba_show_overview() {
    banner; section "SAMBA STATUS AND SHARES"
    samba_installed || { warn "Samba is not installed."; pause; return; }
    printf '%-26s %s\n' "Samba version:" "$(smbd --version 2>/dev/null || echo unknown)"
    printf '%-26s %s\n' "smbd service:" "$(samba_service_active && echo active || echo inactive)"
    printf '%-26s %s\n' "Boot activation:" "$(systemctl is-enabled smbd 2>/dev/null || echo unknown)"
    printf '%-26s %s\n' "Main configuration:" "${SAMBA_CONFIG}"
    printf '%-26s %s\n' "Manager configuration:" "${SAMBA_MANAGER_CONFIG}"
    echo; printf '%-4s %-12s %-24s %s\n' "#" "TYPE" "SHARE" "PATH / PURPOSE"
    local name block path i=0 type purpose
    while IFS= read -r name; do
        [[ -n "${name}" ]] || continue; i=$((i + 1)); block="$(samba_effective_share_block "${name}")"
        path="$(awk -F'= ' '$1 ~ /^[[:space:]]*path[[:space:]]*$/ {print $2; exit}' <<< "${block}")"
        if samba_system_share "${name}"; then type="SYSTEM"; purpose="${path:-dynamic/system share}"
        elif samba_share_is_managed "${name}"; then type="S2S"; purpose="${path:-unknown}"
        else type="EXTERNAL"; purpose="${path:-configured externally}"; fi
        printf '%-4s %-12s %-24s %s\n' "${i}" "${type}" "${name}" "${purpose}"
    done < <(samba_effective_share_names)
    (( i > 0 )) || info "No configured shares found."
    echo; info "Dynamic user shares generated by [homes] are represented by the single SYSTEM entry 'homes'."
    info "IPC$ is generated at runtime and is not an importable static share."
    pause
}

samba_create_share() {
    banner; section "CREATE MANAGED SAMBA SHARE"
    samba_installed || { error "Samba is not installed."; pause; return; }
    local name path group owner backup_main backup_manager path_existed=0 group_needs_create=0 old_uid="" old_gid="" old_mode=""
    echo "Creates one shared read/write workspace for members of an existing Linux group."
    echo "New paths must be below /srv. Files are private to owner/group (0660); directories use 2770."
    echo "B = Back    E = Exit"; echo
    read -r -p "Share name: " name
    [[ "${name}" =~ ^[Bb]$ ]] && return; [[ "${name}" =~ ^[Ee]$ ]] && { clear_screen; exit 0; }
    valid_samba_share_name "${name}" || { error "Use 1-64 letters, numbers, spaces, dot, underscore or hyphen; reserved names are rejected."; pause; return; }
    samba_effective_share_names | grep -Fxiq "${name}" && { error "A share with this name already exists."; pause; return; }
    read -r -p "Directory below /srv (example /srv/share): " path
    valid_new_samba_path "${path}" || { error "Enter a safe absolute path below /srv."; pause; return; }
    samba_path_resolves_safely "${path}" || { error "The path is not canonical or traverses a symbolic link; use a direct path below /srv."; pause; return; }
    read -r -p "Existing Linux group [smbshare]: " group; group="${group:-smbshare}"
    valid_samba_group_name "${group}" || { error "The Linux group name is invalid."; pause; return; }
    if ! getent group "${group}" >/dev/null; then
        info "Linux group '${group}' does not exist."
        group_needs_create=1
    fi
    read -r -p "Existing Linux owner user: " owner
    id "${owner}" >/dev/null 2>&1 || { error "The Linux user does not exist."; pause; return; }
    banner; section "SAMBA SHARE PREVIEW"
    printf '%-24s %s\n' "Share:" "${name}"; printf '%-24s %s\n' "Path:" "${path}"
    printf '%-24s %s\n' "Allowed users:" "@${group}"; printf '%-24s %s\n' "Owner/group:" "${owner}:${group}"
    (( group_needs_create == 1 )) && printf '%-24s %s\n' "Linux group:" "will be created"
    printf '%-24s %s\n' "Files/directories:" "0660 / 2770"; printf '%-24s %s\n' "Guest access:" "disabled"
    echo; warn "Members of ${group} can create, modify and delete shared content."
    confirm_yes_no "Create this managed share?" "N" || return
    if (( group_needs_create == 1 )); then groupadd "${group}" || { error "The Linux group could not be created."; pause; return; }; fi
    if [[ -d "${path}" ]]; then path_existed=1; old_uid="$(stat -c '%u' "${path}")"; old_gid="$(stat -c '%g' "${path}")"; old_mode="$(stat -c '%a' "${path}")"; fi
    touch "${SAMBA_MANAGER_CONFIG}"; chmod 0644 "${SAMBA_MANAGER_CONFIG}"
    backup_main="$(samba_backup_file "${SAMBA_CONFIG}" smb.conf)"; backup_manager="$(samba_backup_file "${SAMBA_MANAGER_CONFIG}" manager-shares)"
    if ! mkdir -p -- "${path}" || ! chown "${owner}:${group}" "${path}" || ! chmod 2770 "${path}"; then
        (( path_existed == 1 )) && { chown "${old_uid}:${old_gid}" "${path}"; chmod "${old_mode}" "${path}"; }
        (( group_needs_create == 1 )) && groupdel "${group}" 2>/dev/null || true
        error "The share directory could not be prepared."; pause; return 1
    fi
    samba_ensure_manager_include && samba_write_managed_share "${name}" "${path}" "${group}" && testparm -s "${SAMBA_CONFIG}" >/dev/null 2>&1 || {
        samba_restore_backup "${backup_main}" "${SAMBA_CONFIG}"; samba_restore_backup "${backup_manager}" "${SAMBA_MANAGER_CONFIG}"; rm -f -- "${SAMBA_SHARE_DIR}/${name}.share"
        if (( path_existed == 1 )); then chown "${old_uid}:${old_gid}" "${path}"; chmod "${old_mode}" "${path}"; else rmdir -- "${path}" 2>/dev/null || true; fi
        (( group_needs_create == 1 )) && groupdel "${group}" 2>/dev/null || true
        error "Configuration validation failed. The Samba configuration was rolled back automatically."
        printf '%-24s %s\n' "Main backup:" "${backup_main}"; printf '%-24s %s\n' "Manager backup:" "${backup_manager}"; pause; return 1; }
    systemctl reload smbd && ok "Share created and Samba reloaded." || warn "Share saved, but smbd reload failed."
    printf '%-24s %s\n' "Main backup:" "${backup_main}"; printf '%-24s %s\n' "Manager backup:" "${backup_manager}"; pause
}

samba_takeover_share() {
    banner; section "TAKE OVER EXISTING SAMBA SHARE"
    samba_installed || { error "Samba is not installed."; pause; return; }
    local -a names=(); local name type i=0 choice source effective path group backup_source backup_main backup_manager before after
    while IFS= read -r name; do
        samba_system_share "${name}" && continue
        samba_share_is_managed "${name}" && continue
        names+=("${name}"); i=$((i + 1)); printf '  [%d] %s\n' "${i}" "${name}"
    done < <(samba_effective_share_names)
    (( ${#names[@]} > 0 )) || { info "No external static share is available for take-over."; pause; return; }
    echo; echo "B = Back    E = Exit"; read -r -p "Share number: " choice
    [[ "${choice}" =~ ^[Bb]$ ]] && return; [[ "${choice}" =~ ^[Ee]$ ]] && { clear_screen; exit 0; }
    [[ "${choice}" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#names[@]} )) || { error "Invalid selection."; pause; return; }
    name="${names[$((choice - 1))]}"; source="$(samba_find_raw_share_source "${name}" 2>/dev/null || true)"
    [[ -n "${source}" ]] || { error "The source block is not unique and cannot be taken over safely."; info "The share remains EXTERNAL and unchanged."; pause; return; }
    [[ "${source}" != "${SAMBA_MANAGER_CONFIG}" ]] || { error "The share is already in the manager file but has no valid state marker."; pause; return; }
    effective="$(samba_effective_share_block "${name}")"
    path="$(awk -F'= ' '$1 ~ /^[[:space:]]*path[[:space:]]*$/ {print $2; exit}' <<< "${effective}")"
    group="$(awk -F'= ' '$1 ~ /^[[:space:]]*force group[[:space:]]*$/ {print $2; exit}' <<< "${effective}")"
    if [[ -z "${group}" ]]; then group="$(awk -F'= ' '$1 ~ /^[[:space:]]*valid users[[:space:]]*$/ {for(i=2;i<=NF;i++) if($i ~ /^@/) {sub(/^@/,"",$i); print $i; exit}}' <<< "${effective}")"; fi
    [[ -n "${path}" && -n "${group}" ]] || { error "Take-over requires an effective path and group-based access/force group."; info "This external share remains unchanged."; pause; return; }
    getent group "${group}" >/dev/null || { error "The effective Linux group '${group}' does not exist."; pause; return; }
    banner; section "SAMBA TAKE-OVER PREVIEW"
    printf '%-24s %s\n' "Share:" "${name}"; printf '%-24s %s\n' "Source file:" "${source}"
    printf '%-24s %s\n' "Path:" "${path}"; printf '%-24s %s\n' "Managed group:" "${group}"
    echo; info "The complete effective share block shown by testparm will be preserved."
    warn "Formatting and comments from the original source are not part of Samba's effective configuration."
    confirm_yes_no "Take over this share?" "N" || return
    touch "${SAMBA_MANAGER_CONFIG}"; chmod 0644 "${SAMBA_MANAGER_CONFIG}"
    backup_source="$(samba_backup_file "${source}" takeover-source)"; backup_main="$(samba_backup_file "${SAMBA_CONFIG}" smb.conf)"; backup_manager="$(samba_backup_file "${SAMBA_MANAGER_CONFIG}" manager-shares)"
    before="${effective}"
    samba_remove_share_block_from_file "${source}" "${name}" && samba_ensure_manager_include && samba_write_imported_share "${name}" "${effective}" "${path}" "${group}" || {
        samba_restore_backup "${backup_source}" "${source}"; samba_restore_backup "${backup_main}" "${SAMBA_CONFIG}"; samba_restore_backup "${backup_manager}" "${SAMBA_MANAGER_CONFIG}"; rm -f -- "${SAMBA_SHARE_DIR}/${name}.share"
        error "Take-over write failed and was rolled back automatically."; printf '%-24s %s\n' "Source backup:" "${backup_source}"; printf '%-24s %s\n' "Manager backup:" "${backup_manager}"; pause; return 1; }
    if ! testparm -s "${SAMBA_CONFIG}" >/dev/null 2>&1; then
        samba_restore_backup "${backup_source}" "${source}"; samba_restore_backup "${backup_main}" "${SAMBA_CONFIG}"; samba_restore_backup "${backup_manager}" "${SAMBA_MANAGER_CONFIG}"; rm -f -- "${SAMBA_SHARE_DIR}/${name}.share"
        error "Samba rejected the converted configuration; take-over was rolled back automatically."
        printf '%-24s %s\n' "Source backup:" "${backup_source}"; printf '%-24s %s\n' "Manager backup:" "${backup_manager}"; pause; return 1
    fi
    after="$(samba_effective_share_block "${name}")"
    systemctl reload smbd && ok "Share taken over and Samba reloaded." || warn "Configuration is valid, but smbd reload failed."
    printf '%-24s %s\n' "Source backup:" "${backup_source}"; printf '%-24s %s\n' "Manager backup:" "${backup_manager}"
    if [[ "${before}" != "${after}" ]]; then warn "The effective block differs after reload; compare it with the retained backups."; else ok "Effective share settings were preserved."; fi
    pause
}

samba_show_users() {
    banner; section "SAMBA USERS"
    samba_installed || { error "Samba is not installed."; pause; return; }
    printf '%-22s %-12s %-14s %-20s %s\n' "USER" "SAMBA" "LINUX TYPE" "HOME" "GROUPS"
    local user entry shell home type groups flags samba_status
    while IFS=: read -r user _; do
        entry="$(getent passwd "${user}" || true)"; shell="$(cut -d: -f7 <<< "${entry}")"; home="$(cut -d: -f6 <<< "${entry}")"
        flags="$(pdbedit -Lv -u "${user}" 2>/dev/null | awk -F: '/Account Flags/ {gsub(/[[:space:]]/,"",$2); print $2; exit}')"
        [[ "${flags}" == *D* ]] && samba_status="DISABLED" || samba_status="ENABLED"
        if [[ -z "${entry}" ]]; then type="MISSING"; groups="-"; home="-"
        elif [[ "${shell}" == */nologin || "${shell}" == */false ]]; then type="SAMBA ONLY"; groups="$(id -nG "${user}" 2>/dev/null || echo '-')"
        else type="NORMAL"; groups="$(id -nG "${user}" 2>/dev/null || echo '-')"; fi
        printf '%-22s %-12s %-14s %-20s %s\n' "${user}" "${samba_status}" "${type}" "${home}" "${groups}"
    done < <(pdbedit -L 2>/dev/null)
    echo; info "NORMAL users may also log in to Linux; SAMBA ONLY users use a nologin shell."
    pause
}

samba_add_user() {
    banner; section "ADD SAMBA USER"
    samba_installed || { error "Samba is not installed."; pause; return; }
    local mode user group choice
    echo "  [1] Add Samba access to an existing Linux user"
    echo "  [2] Create a normal Linux user and add Samba access"
    echo "  [3] Create a Samba-only Linux account (no shell login)"
    echo "  [B] Back    [E] Exit"; echo; read -r -p "Account type: " mode
    [[ "${mode}" =~ ^[Bb]$ ]] && return; [[ "${mode}" =~ ^[Ee]$ ]] && { clear_screen; exit 0; }
    [[ "${mode}" =~ ^[123]$ ]] || { error "Invalid selection."; pause; return; }
    read -r -p "User name: " user
    [[ "${user}" =~ ^[A-Za-z0-9_.-]{1,32}$ ]] || { error "The user name contains unsupported characters."; pause; return; }
    pdbedit -L 2>/dev/null | cut -d: -f1 | grep -Fxq "${user}" && { error "This Samba user already exists."; pause; return; }
    if [[ "${mode}" == "1" ]]; then id "${user}" >/dev/null 2>&1 || { error "The Linux user does not exist."; pause; return; }
    elif ! [[ "${user}" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then error "New Debian users require a lower-case standard user name."; pause; return
    elif id "${user}" >/dev/null 2>&1; then error "The Linux user already exists; choose option 1."; pause; return
    fi
    read -r -p "Share group to join [smbshare]: " group; group="${group:-smbshare}"
    getent group "${group}" >/dev/null || { error "The Linux group does not exist."; pause; return; }
    banner; section "SAMBA USER PREVIEW"
    printf '%-24s %s\n' "User:" "${user}"; printf '%-24s %s\n' "Account type:" "$([[ "${mode}" == 1 ]] && echo existing || { [[ "${mode}" == 2 ]] && echo normal || echo 'Samba only'; })"
    printf '%-24s %s\n' "Share group:" "${group}"; echo
    warn "The Samba password is entered interactively and is not printed by the manager."
    confirm_yes_no "Create/enable this Samba account?" "N" || return
    case "${mode}" in 2) adduser "${user}" || { error "Linux user creation failed."; pause; return; } ;; 3) useradd -M -s /usr/sbin/nologin "${user}" || { error "Linux account creation failed."; pause; return; } ;; esac
    usermod -aG "${group}" "${user}" || { error "Could not add the user to ${group}."; pause; return; }
    if smbpasswd -a "${user}"; then ok "Samba user enabled."; else error "Samba password setup failed."; fi
    pause
}

samba_user_actions() {
    banner; section "SAMBA USER ACTIONS"
    samba_installed || { error "Samba is not installed."; pause; return; }
    local user choice group
    read -r -p "Existing Samba user: " user
    pdbedit -L 2>/dev/null | cut -d: -f1 | grep -Fxq "${user}" || { error "Samba user not found."; pause; return; }
    echo; echo "  [1] Change Samba password"; echo "  [2] Enable Samba account"; echo "  [3] Disable Samba account"
    echo "  [4] Add user to an existing share group"; echo "  [5] Remove user from an existing share group"
    echo "  [6] Delete Samba account only (keep Linux user and files)"; echo "  [B] Back"; read -r -p "Action: " choice
    case "${choice}" in
        1) smbpasswd "${user}" && ok "Password changed." || error "Password change failed." ;;
        2) smbpasswd -e "${user}" && ok "Samba account enabled." || error "Enable failed." ;;
        3) smbpasswd -d "${user}" && ok "Samba account disabled." || error "Disable failed." ;;
        4) read -r -p "Existing group: " group; getent group "${group}" >/dev/null && usermod -aG "${group}" "${user}" && ok "Group membership added." || error "Group operation failed." ;;
        5) read -r -p "Existing group: " group; getent group "${group}" >/dev/null || { error "Group not found."; pause; return; }; warn "Removing membership may immediately remove access to associated shares."; confirm_yes_no "Remove ${user} from ${group}?" "N" && { gpasswd -d "${user}" "${group}" && ok "Group membership removed." || error "Group operation failed."; } ;;
        6) warn "The Linux account, home directory and files will be kept."; confirm_yes_no "Delete only the Samba account for ${user}?" "N" && { smbpasswd -x "${user}" && ok "Samba account deleted." || error "Deletion failed."; } ;;
        b|B|0|"") return ;; *) error "Invalid selection." ;;
    esac
    pause
}

samba_delete_managed_share() {
    banner; section "REMOVE MANAGED SAMBA SHARE"
    local -a names=(); local file name choice backup
    for file in "${SAMBA_SHARE_DIR}"/*.share; do [[ -f "${file}" ]] && names+=("$(basename "${file}" .share)"); done
    (( ${#names[@]} > 0 )) || { info "No managed Samba share exists."; pause; return; }
    local i; for i in "${!names[@]}"; do printf '  [%d] %s\n' "$((i + 1))" "${names[$i]}"; done
    echo; read -r -p "Share number (B = Back): " choice
    [[ "${choice}" =~ ^[Bb]$ ]] && return
    [[ "${choice}" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#names[@]} )) || { error "Invalid selection."; pause; return; }
    name="${names[$((choice - 1))]}"; warn "The share definition is removed, but its directory and files are kept."
    confirm_yes_no "Remove managed share '${name}'?" "N" || return
    backup="$(samba_backup_file "${SAMBA_MANAGER_CONFIG}" manager-shares)"
    samba_remove_share_block_from_file "${SAMBA_MANAGER_CONFIG}" "${name}"
    if testparm -s "${SAMBA_CONFIG}" >/dev/null 2>&1; then
        rm -f -- "${SAMBA_SHARE_DIR}/${name}.share"; systemctl reload smbd || true; ok "Share removed; data directory retained."
    else
        samba_restore_backup "${backup}" "${SAMBA_MANAGER_CONFIG}"; error "Validation failed; configuration was rolled back."
    fi
    printf '%-24s %s\n' "Configuration backup:" "${backup}"; pause
}

samba_edit_managed_share() {
    banner; section "EDIT MANAGED SAMBA SHARE"
    local -a names=(); local file name choice current path group backup state_backup
    for file in "${SAMBA_SHARE_DIR}"/*.share; do [[ -f "${file}" ]] && names+=("$(basename "${file}" .share)"); done
    (( ${#names[@]} > 0 )) || { info "No managed Samba share exists."; pause; return; }
    local i; for i in "${!names[@]}"; do printf '  [%d] %s\n' "$((i + 1))" "${names[$i]}"; done
    echo; read -r -p "Share number (B = Back): " choice; [[ "${choice}" =~ ^[Bb]$ ]] && return
    [[ "${choice}" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#names[@]} )) || { error "Invalid selection."; pause; return; }
    name="${names[$((choice - 1))]}"; current="$(samba_effective_share_block "${name}")"
    path="$(awk -F'= ' '$1 ~ /^[[:space:]]*path[[:space:]]*$/ {print $2; exit}' <<< "${current}")"
    group="$(awk -F'= ' '$1 ~ /^[[:space:]]*force group[[:space:]]*$/ {print $2; exit}' <<< "${current}")"
    if [[ -z "${group}" ]]; then group="$(awk -F'= ' '$1 ~ /^[[:space:]]*valid users[[:space:]]*$/ {for(i=2;i<=NF;i++) if($i ~ /^@/) {sub(/^@/,"",$i); print $i; exit}}' <<< "${current}")"; fi
    echo "Editing converts this managed share to the standard shared-workspace profile."
    read -r -p "Directory [${path}]: " choice; path="${choice:-${path}}"
    [[ -d "${path}" ]] || { error "The directory must already exist when editing a share."; pause; return; }
    samba_path_resolves_safely "${path}" || { error "The path is not a direct canonical directory below /srv."; pause; return; }
    read -r -p "Existing Linux group [${group}]: " choice; group="${choice:-${group}}"
    valid_samba_group_name "${group}" && getent group "${group}" >/dev/null || { error "The existing Linux group is invalid."; pause; return; }
    banner; section "SAMBA SHARE EDIT PREVIEW"
    printf '%-24s %s\n' "Share:" "${name}"; printf '%-24s %s\n' "Path:" "${path}"; printf '%-24s %s\n' "Allowed/forced group:" "${group}"
    printf '%-24s %s\n' "Files/directories:" "0660 / 2770"; echo
    warn "The share directory contents and ownership are not changed by this edit."
    confirm_yes_no "Apply this managed share configuration?" "N" || return
    backup="$(samba_backup_file "${SAMBA_MANAGER_CONFIG}" manager-shares)"; state_backup="$(samba_backup_file "${SAMBA_SHARE_DIR}/${name}.share" share-state)"
    samba_remove_share_block_from_file "${SAMBA_MANAGER_CONFIG}" "${name}" && samba_write_managed_share "${name}" "${path}" "${group}"
    if testparm -s "${SAMBA_CONFIG}" >/dev/null 2>&1; then systemctl reload smbd || true; ok "Managed share updated."
    else samba_restore_backup "${backup}" "${SAMBA_MANAGER_CONFIG}"; samba_restore_backup "${state_backup}" "${SAMBA_SHARE_DIR}/${name}.share"; error "Validation failed; configuration was rolled back."; fi
    printf '%-24s %s\n' "Configuration backup:" "${backup}"; pause
}

samba_permissions_check() {
    banner; section "SAMBA PATH AND PERMISSION CHECK"
    samba_installed || { error "Samba is not installed."; pause; return; }
    local name block path valid force_group
    read -r -p "Configured share name: " name
    block="$(samba_effective_share_block "${name}")"; [[ -n "${block}" ]] || { error "Share not found."; pause; return; }
    path="$(awk -F'= ' '$1 ~ /^[[:space:]]*path[[:space:]]*$/ {print $2; exit}' <<< "${block}")"
    valid="$(awk -F'= ' '$1 ~ /^[[:space:]]*valid users[[:space:]]*$/ {$1=""; sub(/^= /,""); print; exit}' <<< "${block}")"
    force_group="$(awk -F'= ' '$1 ~ /^[[:space:]]*force group[[:space:]]*$/ {print $2; exit}' <<< "${block}")"
    printf '%-24s %s\n' "Share:" "${name}"; printf '%-24s %s\n' "Path:" "${path:-dynamic/not explicit}"
    printf '%-24s %s\n' "Valid users:" "${valid:-not restricted here}"; printf '%-24s %s\n' "Force group:" "${force_group:-not configured}"
    if [[ -n "${path}" && -d "${path}" ]]; then ok "Share directory exists."; stat -c 'Owner/group:             %U:%G%nMode:                    %a (%A)' "${path}"
    elif [[ -n "${path}" ]]; then error "Share directory does not exist."; else info "Dynamic/system share has no fixed path in this block."; fi
    echo; info "This check does not recursively inspect or modify file ownership."
    if samba_share_is_managed "${name}" && [[ -n "${path}" && -d "${path}" && -n "${force_group}" ]]; then
        echo; if confirm_yes_no "Repair only the share root directory group and mode to ${force_group}:2770?" "N"; then
            chgrp "${force_group}" "${path}" && chmod 2770 "${path}" && ok "Share root permissions repaired; contents were not changed." || error "Permission repair failed."
        fi
    fi
    pause
}

samba_diagnostics() {
    banner; section "SAMBA SERVICE AND CONFIGURATION DIAGNOSTICS"
    samba_installed || { error "Samba is not installed."; pause; return; }
    samba_service_active && ok "smbd.service is active." || error "smbd.service is not active."
    systemctl is-enabled --quiet smbd 2>/dev/null && ok "smbd.service is enabled at boot." || warn "smbd.service is not enabled at boot."
    if testparm -s "${SAMBA_CONFIG}" >/dev/null 2>&1; then ok "testparm accepts the effective configuration."; else error "testparm reports an invalid configuration."; testparm -s "${SAMBA_CONFIG}" 2>&1 || true; fi
    if ss -lnt 2>/dev/null | awk '$4 ~ /:445$/ {found=1} END{exit !found}'; then ok "TCP port 445 is listening."; else warn "No TCP listener was found on port 445."; fi
    command_available pdbedit && ok "Samba user database is readable ($(pdbedit -L 2>/dev/null | wc -l) accounts)." || error "pdbedit is unavailable."
    [[ -f "${SAMBA_MANAGER_CONFIG}" ]] && info "Manager include: ${SAMBA_MANAGER_CONFIG}" || info "No manager share include has been created yet."
    echo; info "Recent smbd journal:"; journalctl -u smbd -n 20 --no-pager 2>/dev/null || true
    echo; info "Diagnostics did not change Samba, users, files or firewall rules."; pause
}

samba_reload() {
    banner; section "VALIDATE AND RELOAD SAMBA"
    samba_installed || { error "Samba is not installed."; pause; return; }
    if ! testparm -s "${SAMBA_CONFIG}" >/dev/null 2>&1; then error "Configuration is invalid; smbd will not be reloaded."; testparm -s "${SAMBA_CONFIG}" 2>&1 || true; pause; return; fi
    ok "Configuration validation passed."; confirm_yes_no "Reload smbd now?" "N" || return
    systemctl reload smbd && ok "Samba reloaded without interrupting the service." || error "smbd reload failed."
    pause
}

samba_ufw_guidance() {
    banner; section "SAMBA FIREWALL GUIDANCE"
    echo "SMB file sharing normally uses TCP destination port 445."
    echo "Allow only trusted LAN, WireGuard or S2S source networks; do not expose SMB to the public Internet."
    echo "A provider firewall is separate from local UFW."
    echo
    if ufw_installed; then
        ufw_active && printf '%-24s %s\n' "UFW status:" "active" || printf '%-24s %s\n' "UFW status:" "inactive"
        echo; echo "Create a permanent TCP rule for port 445 with a trusted IPv4/CIDR source."
        echo; if confirm_yes_no "Open the guided permanent UFW rule wizard now?" "N"; then add_ufw_rule permanent; return; fi
    else info "UFW is not installed. It can be installed separately from [22] UFW."; fi
    echo; warn "Never choose source 'any' for SMB on an Internet-reachable server."; pause
}

samba_management_menu() {
    while :; do
        banner; section "SAMBA / FILE SHARES"
        if samba_installed; then
            printf '%-24s %s\n' "Installation:" "present"; printf '%-24s %s\n' "smbd service:" "$(samba_service_active && echo active || echo inactive)"
        else warn "Samba is not installed. Viewing this menu does not install anything."; fi
        cat <<'EOF'

  [1] Show Samba status and all shares
  [2] Install Samba
  [3] Create shared group workspace
  [4] Take over existing external share
  [5] Edit managed shared workspace
  [6] Remove managed share (keep directory and files)
  [7] Show Samba users
  [8] Add Samba user
  [9] Password / enable / disable / group / delete user
  [10] Check / repair share root permissions
  [11] Samba service and configuration diagnostics
  [12] Validate and reload Samba
  [13] SMB / UFW guidance
  [B] Back to main menu
  [E] Exit
EOF
        echo; local choice; read -r -p "Selection: " choice
        case "${choice}" in
            1) samba_show_overview ;; 2) samba_install ;; 3) samba_create_share ;; 4) samba_takeover_share ;;
            5) samba_edit_managed_share ;; 6) samba_delete_managed_share ;; 7) samba_show_users ;; 8) samba_add_user ;;
            9) samba_user_actions ;; 10) samba_permissions_check ;; 11) samba_diagnostics ;; 12) samba_reload ;; 13) samba_ufw_guidance ;;
            b|B|0|"") return ;; e|E) clear_screen; echo "Bye."; exit 0 ;; *) error "Invalid selection."; sleep 1 ;;
        esac
    done
}

# End Samba / file-share management

main_menu() {
    while :; do
        banner
        show_server_identity_summary

        section "CONFIGURED TUNNELS"
        show_existing_tunnels

        if ! preflight_ready; then
            echo
            info "IPsec components are not installed or not ready."
            info "The other manager sections remain available; an IPsec operation offers setup when needed."
        fi

        # General visual separator between the tunnel table and the menu groups.
        echo
        printf '%b' "${C_DIM}"
        table_divider_segment 128
        printf '%b\n' "${C_RESET}"

        local -a menu_config=(
            "  [1] Show tunnel configuration"
            "  [2] Add S2S tunnel"
            "  [3] Add remote network to tunnel"
            "  [4] Remove remote network from tunnel"
            "  [5] Show UniFi configuration"
            "  [6] Rename tunnel display name"
        )

        local -a menu_operations=(
            "  [7] Install tunnel on Debian"
            "  [8] Re-apply tunnel configuration"
            "  [9] Reconnect tunnel"
            "  [10] Tunnel diagnostics"
        )

        local -a menu_remove=(
            "  [11] Uninstall tunnel from Debian (keep definition + PSK)"
            "  [12] Delete tunnel completely"
        )

        local -a menu_import=(
            "  [13] Discover / import existing tunnels"
            "  [14] Take over imported tunnel"
            "  [15] Show Take Over backups"
        )

        local -a menu_export=(
            "  [16] Tunnel backup / restore"
            "  [17] Create Debian peer bundle"
            "  [18] Transfer Debian peer bundle via SCP"
            "  [19] Import Debian peer bundle"
        )

        local -a menu_system=(
            "  [20] Show system status"
            "  [21] WireGuard"
            "  [22] UFW"
            "  [23] Access Check (read-only)"
            "  [24] IPTABLES / Packet Filter (read-only)"
            "  [25] Cron / Scheduled Tasks"
            "  [26] Samba / File Shares"
        )

        render_menu_pair \
            "TUNNEL CONFIGURATION" "${C_CYAN}" menu_config \
            "TUNNEL OPERATIONS" "${C_GREEN}" menu_operations

        render_menu_pair \
            "REMOVE / DELETE" "${C_YELLOW}" menu_remove \
            "IMPORT / TAKE OVER" "${C_BLUE}" menu_import

        render_menu_pair \
            "EXPORT / TRANSFER" "${C_GREEN}" menu_export \
            "SYSTEM / VPN / FIREWALL / CRON / SAMBA" "${C_CYAN}" menu_system

        echo
        echo "  [E] Exit"
        echo

        local choice
        read -r -p "Selection: " choice

        case "${choice}" in
            1) show_configuration ;;
            2) add_tunnel_definition ;;
            3) add_remote_network ;;
            4) remove_remote_network ;;
            5) show_unifi_configuration ;;
            6) rename_tunnel_display_name ;;
            7) run_ipsec_action install_defined_tunnel ;;
            8) run_ipsec_action manual_reapply_tunnel ;;
            9) run_ipsec_action manual_reconnect_tunnel ;;
            10) run_ipsec_action show_tunnel_diagnostics ;;
            11) remove_installed_tunnel ;;
            12) delete_tunnel_completely ;;
            13) run_ipsec_action discover_existing_tunnels ;;
            14) run_ipsec_action takeover_imported_tunnel ;;
            15) show_takeover_backups ;;
            16) tunnel_backup_menu ;;
            17) create_debian_peer_bundle ;;
            18) transfer_debian_peer_bundle ;;
            19) import_debian_peer_bundle ;;
            20) show_system_status ;;
            21) wireguard_menu ;;
            22) ufw_management_menu ;;
            23) access_check_menu ;;
            24) iptables_management_menu ;;
            25) cron_management_menu ;;
            26) samba_management_menu ;;
            [eE]|0) clear_screen; echo "Bye."; exit 0 ;;
            *) error "Invalid selection."; sleep 1 ;;
        esac
    done
}

# ==============================================================================
# Start
# ==============================================================================

main() {
    ensure_root
    init_state_dirs

    WG_STATE_RECONCILED=0
    if wireguard_reconcile_management_state; then
        :
    else
        local rc=$?
        if [[ "${rc}" == "2" ]]; then
            WG_STATE_RECONCILED=1
        fi
    fi

    if repair_peer_type_state_bug; then
        echo
        ok "Recovered Debian peer type metadata from an existing peer bundle."
        info "This repairs tunnel state written by versions 0.40-test through 0.44-test."
        sleep 2
    fi

    if [[ "${WG_STATE_RECONCILED:-0}" == "1" ]]; then
        echo
        warn "WireGuard manager state said MANAGED, but the current wg0.conf is not manager-generated."
        info "The live WireGuard configuration was NOT changed."
        info "Manager state was safely returned to IMPORTED / READ-ONLY."
        sleep 2
    fi

    main_menu
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
