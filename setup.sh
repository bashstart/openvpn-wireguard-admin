#!/usr/bin/env bash
# Debian 11 setup: swap + packages + VPN admin panel + WireGuard/OpenVPN + Caddy + UFW + fail2ban
# Fix: bullseye-backports may be removed from deb.debian.org (404 / no Release file).
# We keep backports disabled by default, optional archived backports support.

set -Eeuo pipefail

# ---------------- Colors & UI ----------------
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
MAGENTA="\033[35m"
CYAN="\033[36m"
RESET="\033[0m"

divider() { echo -e "${CYAN}------------------------------------------------${RESET}"; }
print_error() { echo -e "${RED}[ERROR]: $1${RESET}"; }
print_info() { echo -e "${BLUE}[INFO]: $1${RESET}"; }
print_success() { echo -e "${GREEN}[SUCCESS]: $1${RESET}"; }
print_question() { echo -e "${YELLOW}[QUESTION]: $1${RESET}"; }

# Better error diagnostics
on_error() {
  local exit_code=$?
  local line_no=${1:-"?"}
  local cmd=${2:-"unknown"}
  print_error "Command failed (exit code: ${exit_code}) at line ${line_no}: ${cmd}"
  print_error "Hint: check logs under /root/setup_logs/ and output above."
  exit "${exit_code}"
}
trap 'on_error "${LINENO}" "${BASH_COMMAND}"' ERR

# ---------------- Helpers ----------------
require_root() {
  if [ "$(id -u)" != "0" ]; then
    echo "Error: This script must be run with root privileges." >&2
    echo "Please use 'sudo' or log in as the root user and try again." >&2
    exit 1
  fi
}

ask_yes_no() {
  # Usage: ask_yes_no "Question?" "default" -> returns 0 yes, 1 no
  local q="$1"
  local def="${2:-n}"
  local prompt
  if [[ "$def" == "y" ]]; then prompt="(Y/n)"; else prompt="(y/N)"; fi

  while true; do
    print_question "$q $prompt"
    read -r ans
    ans="$(echo "${ans:-}" | tr '[:upper:]' '[:lower:]')"
    if [[ -z "$ans" ]]; then
      [[ "$def" == "y" ]] && return 0 || return 1
    fi
    case "$ans" in
      y|yes) return 0 ;;
      n|no) return 1 ;;
      *) print_error "Please answer yes/y or no/n." ;;
    esac
  done
}

get_user_choice() {
  # Compatibility wrapper for older script usage
  local q="$1"
  if ask_yes_no "$q" "n"; then return 0; else return 1; fi
}

safe_mkdir() { mkdir -p "$1"; }

# ---------------- Logging ----------------
LOG_DIR="/root/setup_logs"
safe_mkdir "$LOG_DIR"
MAIN_LOG="$LOG_DIR/setup_$(date +%F_%H-%M-%S).log"
touch "$MAIN_LOG"
exec > >(tee -a "$MAIN_LOG") 2>&1

# ---------------- APT Robust Functions ----------------
APT_FORCE_IPV4=0

apt_set_force_ipv4() {
  APT_FORCE_IPV4=1
  mkdir -p /etc/apt/apt.conf.d
  cat > /etc/apt/apt.conf.d/99force-ipv4 <<'EOF'
Acquire::ForceIPv4 "true";
EOF
  print_info "APT is now configured to force IPv4."
}

apt_retry() {
  # Usage: apt_retry "description" command...
  local desc="$1"; shift
  local tries=3
  local i=1

  print_info "$desc"
  while (( i <= tries )); do
    if "$@"; then
      print_success "$desc (ok)"
      return 0
    fi
    print_error "$desc failed (attempt $i/$tries). Retrying in 3s..."
    sleep 3
    ((i++))
  done

  if [[ "$APT_FORCE_IPV4" -eq 0 ]]; then
    print_info "Trying again with IPv4 forced (common fix for provider IPv6 issues)..."
    apt_set_force_ipv4
    i=1
    while (( i <= tries )); do
      if "$@"; then
        print_success "$desc (ok with ForceIPv4)"
        return 0
      fi
      print_error "$desc failed with ForceIPv4 (attempt $i/$tries). Retrying in 3s..."
      sleep 3
      ((i++))
    done
  fi

  print_error "$desc failed after retries."
  return 1
}

apt_update_raw() {
  # raw update, used by auto-fix logic
  apt-get update -y
}

apt_update() {
  apt_retry "Running apt-get update..." apt_update_raw
}

apt_upgrade() {
  export DEBIAN_FRONTEND=noninteractive
  apt_retry "Running apt-get -y upgrade..." \
    apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" upgrade
}

apt_install() {
  export DEBIAN_FRONTEND=noninteractive
  apt_retry "Installing packages: $*" apt-get install -y "$@"
}

# ---------------- OS Detection & Sources ----------------
detect_distro() {
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO="${ID:-unknown}"
    VERSION_ID="${VERSION_ID:-unknown}"
    CODENAME="${VERSION_CODENAME:-}"
  else
    DISTRO="unknown"
    VERSION_ID="unknown"
    CODENAME=""
  fi
}

# Default (recommended): Debian 11 without backports (backports often removed -> 404)
write_sources_debian11_no_backports() {
  cat > /etc/apt/sources.list <<'EOF'
deb https://deb.debian.org/debian bullseye main contrib non-free
deb https://deb.debian.org/debian bullseye-updates main contrib non-free
deb https://security.debian.org/debian-security bullseye-security main contrib non-free
EOF
}

# Optional: archived backports (ONLY if user really needs it)
# Note: archive can require disabling Valid-Until checks.
write_sources_debian11_archived_backports() {
  cat > /etc/apt/sources.list <<'EOF'
deb https://deb.debian.org/debian bullseye main contrib non-free
deb https://deb.debian.org/debian bullseye-updates main contrib non-free
deb https://security.debian.org/debian-security bullseye-security main contrib non-free

# Bullseye-backports is archived (deb.debian.org may return 404/no Release).
# Use archive.debian.org if you really need backports.
deb http://archive.debian.org/debian bullseye-backports main contrib non-free
EOF

  mkdir -p /etc/apt/apt.conf.d
  cat > /etc/apt/apt.conf.d/99archive-debian <<'EOF'
Acquire::Check-Valid-Until "false";
EOF
}

# Auto-fix for broken backports entry: remove/comment it and re-run apt update
fix_backports_if_broken() {
  # Detect the specific error in the last apt output (log contains it too),
  # but we can just test connectivity by running apt_update_raw and checking stderr in temp.
  local tmp_out
  tmp_out="$(mktemp)"
  set +e
  apt-get update -y >"$tmp_out" 2>&1
  local rc=$?
  set -e

  if [[ $rc -eq 0 ]]; then
    rm -f "$tmp_out"
    return 0
  fi

  if grep -qE "bullseye-backports.*(404|does not have a Release file|No Release file)" "$tmp_out"; then
    print_error "Detected broken bullseye-backports repository (404 / no Release file). Disabling backports and retrying..."
    # Remove backports lines from sources.list
    if [[ -f /etc/apt/sources.list ]]; then
      sed -i '/bullseye-backports/d' /etc/apt/sources.list
    fi
    rm -f "$tmp_out"
    apt_update
    return 0
  fi

  # Not a backports problem
  print_error "apt-get update failed, and it does not look like a bullseye-backports 404 issue."
  print_error "Please inspect: $MAIN_LOG"
  cat "$tmp_out" || true
  rm -f "$tmp_out"
  return 1
}

# ---------------- Swap Setup ----------------
setup_swap() {
  divider
  print_info "Setting up swap..."
  divider

  safe_mkdir /var/swapmemory
  local total_ram
  total_ram="$(free -m | awk '/Mem:/ {print $2}')"
  if [[ -z "$total_ram" ]]; then
    print_error "Could not detect total RAM."
    exit 1
  fi

  local swap_size
  if (( total_ram < 1024 )); then swap_size="$total_ram"; else swap_size=1000; fi
  print_success "Swap size determined: ${swap_size} MB."

  local swapfile="/var/swapmemory/swapfile"

  if [[ -f "$swapfile" ]]; then
    if ask_yes_no "Swapfile already exists. Resize to ${swap_size} MB?" "n"; then
      print_info "Turning off existing swap..."
      swapoff "$swapfile" || true

      print_info "Resizing swapfile..."
      rm -f "$swapfile"
      umask 077
      dd if=/dev/zero of="$swapfile" bs=1M count="$swap_size" status=progress
      chmod 600 "$swapfile"
      mkswap "$swapfile"
      swapon "$swapfile"
      print_success "Swap resized to ${swap_size} MB."
    else
      print_info "Keeping current swap size."
    fi
  else
    print_info "Creating new swapfile..."
    umask 077
    dd if=/dev/zero of="$swapfile" bs=1M count="$swap_size" status=progress
    chmod 600 "$swapfile"
    mkswap "$swapfile"
    swapon "$swapfile"

    if ! grep -qE "^[^#]*\s${swapfile//\//\\/}\s" /etc/fstab; then
      echo "$swapfile none swap sw 0 0" >> /etc/fstab
      print_info "Added swap entry to /etc/fstab."
    else
      print_info "Swap entry already exists in /etc/fstab."
    fi

    print_success "Swap of size ${swap_size} MB created."
  fi

  divider
  print_info "Current memory & swap usage:"
  free -m
}

# ---------------- Sysctl Tuning ----------------
apply_sysctl_tuning() {
  divider
  print_info "Applying network/sysctl tuning..."
  divider

  # Important: DO NOT disable ASLR (kernel.randomize_va_space=0) for security.
  cat > /etc/sysctl.d/99-vpn-tuning.conf <<'EOF'
# VPN / network tuning (conservative)
net.core.rmem_max = 26214400
net.core.rmem_default = 26214400
net.core.wmem_max = 26214400
net.core.wmem_default = 26214400
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 4096
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 5
EOF

  sysctl --system >/dev/null
  print_success "Sysctl tuning applied and persisted in /etc/sysctl.d/99-vpn-tuning.conf"
}

# ---------------- Packages & Services ----------------
install_base_packages() {
  divider
  print_info "Fetching distribution information..."
  divider
  detect_distro

  if [[ "$DISTRO" != "debian" ]]; then
    print_error "Unsupported distribution: $DISTRO"
    exit 1
  fi

  print_info "Detected Debian (VERSION_ID=$VERSION_ID, CODENAME=${CODENAME:-unknown})."

  if [[ "$VERSION_ID" == "11" ]]; then
    divider
    print_info "Configuring Debian 11 sources (WITHOUT backports by default)..."
    write_sources_debian11_no_backports
    print_success "Sources set for Debian 11 Bullseye (no backports)."

    # Optional: archived backports
    divider
    print_info "Note: bullseye-backports can be removed from deb.debian.org and cause apt failures."
    if ask_yes_no "Do you want to enable ARCHIVED bullseye-backports (archive.debian.org)?" "n"; then
      print_info "Enabling archived backports..."
      write_sources_debian11_archived_backports
      print_success "Archived backports enabled (archive.debian.org)."
    else
      print_info "Backports remain disabled (recommended)."
    fi
  else
    print_error "Detected unsupported Debian version: $VERSION_ID"
    print_error "Recommended OS: Debian 11 Minimal."
    if ! ask_yes_no "Proceed anyway?" "n"; then
      print_error "Installation aborted."
      exit 1
    fi
    print_info "Continuing on unsupported version (best effort)."
  fi

  divider
  print_info "Updating system packages..."
  divider

  # First attempt normal update; if it fails due to backports, auto-disable and retry.
  if ! apt_update; then
    print_error "Initial apt update failed, trying auto-fix for backports..."
    fix_backports_if_broken
  fi

  apt_upgrade

  divider
  print_info "Installing necessary packages..."
  divider

  apt_install ufw git wget python3 python3-pip screen gpg fail2ban curl cron ca-certificates \
              debian-keyring debian-archive-keyring apt-transport-https systemd

  print_success "Base packages installed."
}

setup_time_sync() {
  divider
  print_info "Synchronizing system time..."
  divider

  if systemctl list-unit-files | grep -q '^systemd-timesyncd\.service'; then
    systemctl enable --now systemd-timesyncd
    timedatectl set-ntp true || true
    print_success "Time sync enabled via systemd-timesyncd."
  else
    print_info "systemd-timesyncd not found, installing ntp..."
    apt_install ntp
    systemctl enable --now ntp
    print_success "Time sync enabled via ntp."
  fi
}

setup_fail2ban() {
  divider
  print_info "Enabling fail2ban..."
  divider
  systemctl enable --now fail2ban
  print_success "fail2ban is enabled and running."
}

# ---------------- Web Admin Panel ----------------
setup_web_admin_panel() {
  divider
  print_info "Setting up the web admin panel..."
  divider

  cd /root

  if [[ -d /root/vpn ]]; then
    if ask_yes_no "/root/vpn already exists. Remove and re-clone?" "n"; then
      rm -rf /root/vpn
    else
      print_info "Using existing /root/vpn directory."
    fi
  fi

  if [[ ! -d /root/vpn ]]; then
    git clone https://github.com/dashroshan/openvpn-wireguard-admin vpn
    print_success "Cloned the Web admin panel successfully."
  fi

  cd /root/vpn

  python3 -m pip install --upgrade pip setuptools wheel

  python3 -m pip install -r requirements.txt
  print_success "Requirements for Web admin panel installed successfully."

  divider
  print_question "Web admin panel username: "
  read -r adminuser

  while [[ ! "$adminuser" =~ ^[a-zA-Z0-9_]{3,15}$ ]]; do
    print_error "Username should be 3-15 chars and contain only letters/digits/underscore."
    print_question "Web admin panel username: "
    read -r adminuser
  done

  print_question "Web admin panel password: "
  read -rs adminpass
  echo

  while [[ ! "$adminpass" =~ [A-Z] ]] ||
        [[ ! "$adminpass" =~ [a-z] ]] ||
        [[ ! "$adminpass" =~ [0-9] ]] ||
        [[ ${#adminpass} -lt 8 ]] ||
        [[ ${#adminpass} -gt 64 ]]; do
    print_error "Password must be 8-64 chars and include uppercase, lowercase, and a number."
    print_question "Web admin panel password: "
    read -rs adminpass
    echo
  done

  print_question "Confirm password: "
  read -rs adminpass_confirm
  echo

  while [[ "$adminpass" != "$adminpass_confirm" ]]; do
    print_error "Passwords do not match. Try again."
    print_question "Web admin panel password: "
    read -rs adminpass
    echo
    print_question "Confirm password: "
    read -rs adminpass_confirm
    echo
  done

  passwordhash="$(echo -n "$adminpass" | sha256sum | cut -d" " -f1)"

  ADMIN_USER="$adminuser"
  ADMIN_PASSHASH="$passwordhash"
}

# ---------------- VPN Install (WireGuard/OpenVPN) ----------------
install_vpn() {
  divider
  print_info "Setting up VPN service..."
  divider

  while true; do
    print_question "1) WireGuard"
    print_question "2) OpenVPN"
    read -rp "Enter choice [1-2]: " choice

    case "$choice" in
      1)
        vpntype="wireguard"
        print_info "Downloading WireGuard install script..."
        wget -O /root/vpn-install.sh https://raw.githubusercontent.com/Nyr/wireguard-install/master/wireguard-install.sh
        chmod +x /root/vpn-install.sh
        /root/vpn-install.sh
        print_success "WireGuard installed."

        WIREGUARD_CONFIG="/etc/wireguard/wg0.conf"
        if [[ ! -f "$WIREGUARD_CONFIG" ]]; then
          print_error "WireGuard config not found at $WIREGUARD_CONFIG"
          exit 1
        fi

        port="$(grep -Po '(?<=ListenPort\s=\s)\d+' "$WIREGUARD_CONFIG" || true)"
        if [[ -z "$port" ]]; then
          print_error "Failed to extract WireGuard port from $WIREGUARD_CONFIG"
          exit 1
        fi

        ufw allow out on wg0 from any to any || true
        ufw reload || true

        print_info "Setting up logging for WireGuard..."
        LOGFILE_PATH="/var/log/wireguard.log"
        touch "$LOGFILE_PATH"
        chmod 600 "$LOGFILE_PATH"

        cat > /etc/cron.d/wireguard_custom <<'EOF'
@reboot root sleep 20 && /usr/bin/journalctl -u wg-quick@wg0.service -f -n 0 -o cat | /usr/bin/tee -a /var/log/wireguard.log &
EOF

        cat > /etc/fail2ban/jail.d/wireguard.conf <<EOF
[wireguard]
enabled  = true
port     = $port
filter   = wireguard
logpath  = $LOGFILE_PATH
maxretry = 3
EOF
        print_success "Configured fail2ban jail for WireGuard."

        cat > /etc/fail2ban/filter.d/wireguard.conf <<'EOF'
[Definition]
failregex = .*WG:.*\[.*\]: Handshake for peer .* failed for .*: Invalid MAC=
ignoreregex =
EOF
        print_success "Configured fail2ban filter for WireGuard."

        print_question "Choose an option for AdBlock:"
        echo "1. True"
        echo "2. False"
        read -rp "Enter 1 or 2: " adchoice
        case "$adchoice" in
          1) adblock="True" ;;
          2) adblock="False" ;;
          *) print_error "Invalid choice. Exiting."; exit 1 ;;
        esac

        cat > /root/vpn/configWireguard.py <<EOF
wireGuardBlockAds = $adblock
EOF
        print_success "configWireguard.py created."

        CRON_JOB_FILE="/etc/cron.d/wireguard_cron_tasks"
        : > "$CRON_JOB_FILE"

        divider
        print_info "Would you like to set up auto-restart for WireGuard?"
        if get_user_choice "Enable auto-restart?"; then
          print_question "Enter restart interval in hours (e.g., 2 = every 2 hours):"
          read -r restart_interval
          if [[ ! "$restart_interval" =~ ^[0-9]+$ ]] || [[ "$restart_interval" -lt 1 ]] || [[ "$restart_interval" -gt 168 ]]; then
            print_error "Invalid interval. Using 6 hours."
            restart_interval=6
          fi
          echo "@reboot root /usr/bin/systemctl restart wg-quick@wg0" >> "$CRON_JOB_FILE"
          echo "0 */$restart_interval * * * root /usr/bin/systemctl restart wg-quick@wg0" >> "$CRON_JOB_FILE"
          print_success "Auto-restart configured."
        fi

        divider
        print_info "Would you like to enable unattended upgrades (auto updates)?"
        if get_user_choice "Enable automatic updates?"; then
          apt_install unattended-upgrades
          dpkg-reconfigure -f noninteractive unattended-upgrades || true
          print_success "Unattended upgrades enabled."
        fi

        divider
        print_info "Would you like to set up local monitoring for WireGuard?"
        if get_user_choice "Enable monitoring?"; then
          MONITORING_DEST="/root/vpn/wireguard_status.log"
          echo "* * * * * root /usr/bin/wg show > $MONITORING_DEST" >> "$CRON_JOB_FILE"
          print_success "Monitoring enabled: $MONITORING_DEST updated every minute."
        fi

        break
        ;;

      2)
        vpntype="openvpn"
        print_info "Downloading OpenVPN install script..."
        wget -O /root/vpn-install.sh https://raw.githubusercontent.com/Nyr/openvpn-install/master/openvpn-install.sh
        chmod +x /root/vpn-install.sh
        /root/vpn-install.sh
        print_success "OpenVPN installed."

        local_conf="/etc/openvpn/server/server.conf"
        if [[ ! -f "$local_conf" ]]; then
          print_error "OpenVPN config not found at $local_conf"
          exit 1
        fi

        port="$(grep -Po '(?<=^port\s)\d+' "$local_conf" || true)"
        protocol="$(grep -Po '(?<=^proto\s)\w+' "$local_conf" || true)"

        if [[ -z "$port" || -z "$protocol" ]]; then
          print_error "Failed to extract port/protocol from $local_conf"
          exit 1
        fi

        cat > /etc/fail2ban/jail.d/openvpn.conf <<EOF
[openvpn]
enabled  = true
port     = $port
protocol = $protocol
filter   = openvpn
logpath  = /var/log/openvpn.log
maxretry = 3
bantime  = 3600
EOF
        print_success "Configured fail2ban jail for OpenVPN."

        cat > /etc/fail2ban/filter.d/openvpn.conf <<'EOF'
[Definition]
failregex = TLS Auth Error: Auth Username/Password verification failed for peer
ignoreregex =
EOF
        print_success "Configured fail2ban filter for OpenVPN."

        CRON_JOB_FILE="/etc/cron.d/openvpn_cron_tasks"
        : > "$CRON_JOB_FILE"

        divider
        print_info "Would you like to set up auto-restart for OpenVPN?"
        if ask_yes_no "Enable auto-restart?" "n"; then
          print_question "Enter restart interval in hours (e.g., 2 = every 2 hours):"
          read -r restart_interval
          if [[ ! "$restart_interval" =~ ^[0-9]+$ ]] || [[ "$restart_interval" -lt 1 ]] || [[ "$restart_interval" -gt 168 ]]; then
            print_error "Invalid interval. Using 6 hours."
            restart_interval=6
          fi
          echo "@reboot root /usr/bin/systemctl restart openvpn-server@server" >> "$CRON_JOB_FILE"
          echo "0 */$restart_interval * * * root /usr/bin/systemctl restart openvpn-server@server" >> "$CRON_JOB_FILE"
          print_success "Auto-restart configured."
        fi

        divider
        print_info "Would you like to enable unattended upgrades (auto updates)?"
        if ask_yes_no "Enable automatic updates?" "n"; then
          apt_install unattended-upgrades
          dpkg-reconfigure -f noninteractive unattended-upgrades || true
          print_success "Unattended upgrades enabled."
        fi

        divider
        print_info "Would you like to set up local monitoring for OpenVPN?"
        if ask_yes_no "Enable monitoring?" "n"; then
          MONITORING_DEST="/root/vpn/openvpn_status.log"
          echo "* * * * * root cat /etc/openvpn/server/openvpn-status.log > $MONITORING_DEST" >> "$CRON_JOB_FILE"
          print_success "Monitoring enabled: $MONITORING_DEST updated every minute."
        fi

        break
        ;;

      *)
        print_error "Invalid choice. Please select 1 or 2."
        ;;
    esac
  done

  VPN_TYPE="$vpntype"
  VPN_PORT="$port"
  VPN_PROTO="${protocol:-udp}"
}

# ---------------- Web Panel config.py ----------------
write_webpanel_config() {
  divider
  print_info "Writing web admin panel config..."
  divider

  cd /root/vpn

  cat > /root/vpn/config.py <<EOF
import $VPN_TYPE as vpn
creds = {
    "username": "$ADMIN_USER",
    "password": "$ADMIN_PASSHASH",
}
EOF
  print_success "config.py created."
}

# ---------------- fail2ban SSH ----------------
setup_fail2ban_ssh() {
  divider
  print_info "Configuring fail2ban for SSH on port 22..."
  divider

  cat > /etc/fail2ban/jail.d/custom-sshd.conf <<'EOF'
[sshd]
enabled  = true
port     = 22
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 3600
EOF

  systemctl restart fail2ban
  print_success "fail2ban SSH jail configured and fail2ban restarted."
}

# ---------------- UFW ----------------
setup_firewall() {
  divider
  print_info "Configuring firewall (UFW)..."
  divider

  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing

  ufw allow 22/tcp
  if [[ "$VPN_TYPE" == "wireguard" ]]; then
    ufw allow "${VPN_PORT}/udp"
  else
    ufw allow "${VPN_PORT}/${VPN_PROTO}"
  fi
  ufw allow 80/tcp
  ufw allow 443/tcp

  ufw --force enable
  ufw reload

  print_success "UFW enabled. Opened: 22/tcp, 80/tcp, 443/tcp, ${VPN_PORT} (${VPN_TYPE})"
}

# ---------------- Caddy ----------------
install_caddy() {
  divider
  print_info "Installing Caddy..."
  divider

  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/caddy-stable-archive-keyring.gpg] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main" \
    > /etc/apt/sources.list.d/caddy-stable.list

  # Update again (this should now work even if backports was problematic)
  if ! apt_update; then
    print_error "apt update failed after adding Caddy repo. Trying auto-fix for backports..."
    fix_backports_if_broken
  fi

  apt_install caddy
  print_success "Caddy installed."
}

configure_caddy() {
  divider
  print_info "Configuring Caddy reverse proxy..."
  divider

  systemctl stop caddy || true

  local admindomain
  while true; do
    print_question "Enter your Web admin panel domain or subdomain (e.g., sub.example.com): "
    read -r admindomain
    if [[ "$admindomain" =~ ^([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.?)+\.[a-zA-Z]{2,}$ ]]; then
      break
    fi
    print_error "Invalid domain format. Example: panel.example.com"
  done

  cat > /etc/caddy/Caddyfile <<EOF
$admindomain {
    reverse_proxy localhost:5000
}
EOF

  chmod 644 /etc/caddy/Caddyfile
  caddy fmt --overwrite /etc/caddy/Caddyfile

  systemctl enable --now caddy
  caddy reload --config /etc/caddy/Caddyfile

  if systemctl is-active --quiet caddy; then
    print_success "Caddy reverse proxy configured for: $admindomain"
  else
    print_error "Caddy service isn't running."
    exit 1
  fi

  ADMIN_DOMAIN="$admindomain"
}

# ---------------- Startup Script ----------------
setup_startup_script() {
  divider
  print_info "Setting up startup script for web panel..."
  divider

  local script_path="/root/startup.sh"
  cat > "$script_path" <<'EOL'
#!/usr/bin/env bash
set -euo pipefail

sleep 5
cd /root/vpn
nohup python3 main.py > /root/vpn/vpn.log 2>&1 &
EOL

  chmod +x "$script_path"

  local cron_file="/etc/cron.d/my_startup_script"
  if [[ ! -f "$cron_file" ]]; then
    echo "@reboot root $script_path" > "$cron_file"
    chmod 644 "$cron_file"
    print_success "Startup script added to cron (@reboot)."
  else
    print_info "Cron startup file already exists: $cron_file"
  fi
}

# ---------------- Main ----------------
main() {
  require_root

  divider
  print_info "Initializing setup script (Debian 11 hardened)..."
  print_info "Log file: $MAIN_LOG"
  divider

  setup_swap
  apply_sysctl_tuning

  install_base_packages
  setup_time_sync
  setup_fail2ban

  setup_web_admin_panel
  install_vpn
  write_webpanel_config

  setup_fail2ban_ssh
  setup_firewall

  install_caddy
  configure_caddy

  setup_startup_script

  divider
  print_success "Installation finished."
  print_info "Web panel should be available at: https://$ADMIN_DOMAIN"
  print_info "Logs: $MAIN_LOG and /root/vpn/vpn.log"
  divider

  if ask_yes_no "For changes to take effect fully, reboot is recommended. Reboot now?" "n"; then
    print_info "Rebooting now..."
    reboot
  else
    print_success "Please remember to reboot later."
  fi
}

main
