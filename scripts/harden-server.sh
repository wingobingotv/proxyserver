#!/bin/bash
# Hardens the wingobingo-proxy host (Ubuntu / Debian). Safe to run again.
#
#   sudo ./scripts/harden-server.sh                  # firewall, fail2ban, updates, sysctl, NTP, nginx, ssh (safe options)
#   sudo ./scripts/harden-server.sh --ssh-keys-only  # also: no SSH passwords, root only with a key
#
# Environment overrides:
#   EXTRA_TCP_PORTS="2468"          extra inbound TCP ports to open (space separated)
#   PROXY_DIR=/opt/wingobingo-proxy where .env lives (permissions are tightened)
#
# Inbound after this script: the SSH port(s) sshd really listens on (rate-limited),
# 80 and 443 (Nginx), EXTRA_TCP_PORTS. Everything else is dropped.
# The proxy container is bound to 127.0.0.1 and needs no rule.
set -euo pipefail

EXTRA_TCP_PORTS="${EXTRA_TCP_PORTS:-2468}"
PROXY_DIR="${PROXY_DIR:-/opt/wingobingo-proxy}"
SSH_KEYS_ONLY=false

for arg in "$@"; do
  case "$arg" in
    --ssh-keys-only) SSH_KEYS_ONLY=true ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

log()  { printf '\n=== %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }

[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)." >&2; exit 1; }
command -v apt-get >/dev/null || { echo "Only Debian/Ubuntu (apt) is supported." >&2; exit 1; }

for p in $EXTRA_TCP_PORTS; do
  [[ "$p" =~ ^[0-9]+$ ]] && [ "$p" -ge 1 ] && [ "$p" -le 65535 ] || { echo "Invalid port in EXTRA_TCP_PORTS: $p" >&2; exit 2; }
done

# ── SSH ports actually in use (never lock ourselves out) ────────────────────
ssh_ports() {
  {
    sshd -T 2>/dev/null | awk '$1 == "port" { print $2 }'
    ss -Htlnp 2>/dev/null | awk '/"sshd"/ { n = split($4, a, ":"); print a[n] }'
    # Ubuntu 24.04+: socket-activated sshd listens through ssh.socket.
    systemctl show -p Listen ssh.socket 2>/dev/null | grep -oE ':[0-9]+ \(Stream\)' | tr -dc '0-9\n' || true
    # The port of the session running this script, when sudo kept SSH_CONNECTION.
    if [ -n "${SSH_CONNECTION:-}" ]; then echo "$SSH_CONNECTION" | awk '{ print $4 }'; fi
  } | grep -E '^[0-9]+$' | sort -un || true
}
SSH_PORTS="$(ssh_ports || true)"
if [ -z "$SSH_PORTS" ]; then
  warn "could not detect the SSH port; keeping 22 open"
  SSH_PORTS=22
fi
echo "SSH port(s): $(echo "$SSH_PORTS" | tr '\n' ' ')"
echo "Extra TCP port(s): $EXTRA_TCP_PORTS"

# ── Packages ────────────────────────────────────────────────────────────────
log "Installing ufw, fail2ban, unattended-upgrades"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ufw fail2ban python3-systemd unattended-upgrades apt-listchanges >/dev/null

# ── Automatic security updates ──────────────────────────────────────────────
log "Enabling automatic security updates"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true

# ── Time sync (request signatures allow ±300 s) ─────────────────────────────
log "Enabling NTP time sync"
timedatectl set-ntp true 2>/dev/null || warn "timedatectl not available; make sure NTP runs"
timedatectl 2>/dev/null | grep -E 'synchronized|NTP service' || true

# ── Firewall ────────────────────────────────────────────────────────────────
log "Configuring ufw"
sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
for p in $SSH_PORTS; do
  ufw limit "$p/tcp" comment 'ssh (rate limited)' >/dev/null
done
for p in $EXTRA_TCP_PORTS; do
  echo "$SSH_PORTS" | grep -qx "$p" && continue
  ufw allow "$p/tcp" comment 'extra' >/dev/null
done
ufw allow 80/tcp comment 'nginx http (certbot, redirect)' >/dev/null
ufw allow 443/tcp comment 'nginx https' >/dev/null
ufw --force enable >/dev/null
ufw status verbose

# Docker publishes ports through iptables, bypassing ufw. The proxy must stay on 127.0.0.1.
if command -v docker >/dev/null 2>&1; then
  exposed="$(docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null | grep -E '(0\.0\.0\.0|\[::\]|:::)[0-9]+->' || true)"
  if [ -n "$exposed" ]; then
    warn "these containers publish ports on all interfaces (ufw does NOT protect them):"
    echo "$exposed" >&2
  else
    echo "Docker: no container port is published on a public interface."
  fi
fi

# ── fail2ban (SSH brute force) ──────────────────────────────────────────────
log "Configuring fail2ban"
cat > /etc/fail2ban/jail.d/wingobingo-proxy.local <<EOF
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
banaction = ufw

[sshd]
enabled = true
port    = $(echo "$SSH_PORTS" | paste -sd, -)
backend = systemd
EOF
systemctl enable fail2ban >/dev/null 2>&1
systemctl restart fail2ban
fail2ban-client status sshd 2>/dev/null | sed -n '1,4p' || warn "fail2ban sshd jail not running; check: journalctl -u fail2ban"

# ── Kernel network hardening (IP forwarding stays on for Docker) ────────────
log "Applying sysctl hardening"
cat > /etc/sysctl.d/99-wingobingo-proxy.conf <<'EOF'
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF
sysctl --system >/dev/null

# ── Nginx: hide the version on every response ───────────────────────────────
if command -v nginx >/dev/null 2>&1; then
  log "Nginx: server_tokens off"
  conf=/etc/nginx/conf.d/99-wingobingo-hardening.conf
  if grep -rqsE '^\s*server_tokens\s+' /etc/nginx/nginx.conf; then
    echo "nginx.conf already sets server_tokens; left unchanged."
  else
    echo "server_tokens off;" > "$conf"
    if nginx -t 2>/dev/null; then
      systemctl reload nginx
      echo "Applied."
    else
      rm -f "$conf"
      warn "nginx -t failed with server_tokens; change reverted"
    fi
  fi
fi

# ── SSH daemon ──────────────────────────────────────────────────────────────
log "Hardening sshd"
SSHD_DROPIN=/etc/ssh/sshd_config.d/99-wingobingo-hardening.conf
if ! grep -qsE '^\s*Include\s+/etc/ssh/sshd_config\.d/' /etc/ssh/sshd_config; then
  warn "sshd_config does not include sshd_config.d; SSH settings skipped"
else
  {
    echo "# Managed by wingobingo-proxy scripts/harden-server.sh"
    echo "PermitEmptyPasswords no"
    echo "X11Forwarding no"
    echo "MaxAuthTries 4"
    echo "LoginGraceTime 30"
    echo "ClientAliveInterval 300"
    echo "ClientAliveCountMax 2"
  } > "$SSHD_DROPIN"

  if $SSH_KEYS_ONLY; then
    keys=0
    for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
      [ -s "$f" ] && grep -qE '^(ssh-|ecdsa-|sk-)' "$f" && keys=1
    done
    if [ "$keys" -eq 1 ]; then
      {
        echo "PasswordAuthentication no"
        echo "KbdInteractiveAuthentication no"
        echo "PermitRootLogin prohibit-password"
      } >> "$SSHD_DROPIN"
      echo "SSH: passwords disabled (keys only)."
    else
      warn "--ssh-keys-only ignored: no authorized_keys found, passwords stay enabled"
    fi
  fi

  if sshd -t 2>/dev/null; then
    systemctl reload ssh 2>/dev/null || systemctl reload sshd
    echo "sshd reloaded (existing sessions stay open)."
  else
    rm -f "$SSHD_DROPIN"
    warn "sshd -t failed; SSH changes reverted"
  fi
fi

# ── Proxy secrets ───────────────────────────────────────────────────────────
if [ -f "$PROXY_DIR/.env" ]; then
  chmod 600 "$PROXY_DIR/.env"
  echo "$PROXY_DIR/.env is now readable by its owner only."
fi

log "Done"
echo "Open inbound TCP: $(echo "$SSH_PORTS" | tr '\n' ' ')$EXTRA_TCP_PORTS 80 443"
echo "Before closing this session, open a NEW SSH session to confirm you can still log in."
