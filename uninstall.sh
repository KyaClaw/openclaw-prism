#!/usr/bin/env bash
set -euo pipefail

# ── KyaClaw PRISM Uninstaller ──
# Run on the OpenClaw server: bash uninstall.sh (do NOT run with sudo)

# Resolve real user home even if run via sudo
if [ -n "${SUDO_USER:-}" ]; then
  REAL_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
else
  REAL_HOME="$HOME"
fi

INSTALL_DIR="/opt/kyaclaw-prism"
OPENCLAW_DIR="$REAL_HOME/.openclaw"
OPENCLAW_JSON="$OPENCLAW_DIR/openclaw.json"
EXTENSIONS_DIR="$OPENCLAW_DIR/extensions"
SECURITY_DIR="$OPENCLAW_DIR/security"
PLUGIN_LINK="$EXTENSIONS_DIR/kyaclaw-security"

echo "╔══════════════════════════════════════╗"
echo "║  KyaClaw PRISM Uninstaller          ║"
echo "╚══════════════════════════════════════╝"
echo ""
echo "This will remove:"
echo "  - Systemd/launchd services"
echo "  - Plugin symlink ($PLUGIN_LINK)"
echo "  - kyaclaw-security from plugins.allow in openclaw.json"
echo "  - Installation directory ($INSTALL_DIR)"
echo "  - Audit logs ($SECURITY_DIR) (optional)"
echo ""
read -rp "Continue? [y/N] " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
  echo "Cancelled."
  exit 0
fi

# ── 1. Stop and remove systemd services ──
echo "[1/6] Stopping services..."

if command -v systemctl &>/dev/null; then
  for svc in kyaclaw-scanner kyaclaw-proxy kyaclaw-monitor; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
      sudo systemctl stop "$svc"
      echo "  Stopped $svc"
    fi
    if [ -f "/etc/systemd/system/${svc}.service" ]; then
      sudo systemctl disable "$svc" 2>/dev/null || true
      sudo rm -f "/etc/systemd/system/${svc}.service"
      echo "  Removed ${svc}.service"
    fi
  done
  sudo systemctl daemon-reload
fi

# ── 2. Remove launchd services (macOS) ──
if [ "$(uname)" = "Darwin" ]; then
  for plist in com.kyaclaw.scanner com.kyaclaw.proxy com.kyaclaw.monitor; do
    PLIST_PATH="$REAL_HOME/Library/LaunchAgents/${plist}.plist"
    if [ -f "$PLIST_PATH" ]; then
      launchctl unload "$PLIST_PATH" 2>/dev/null || true
      rm -f "$PLIST_PATH"
      echo "  Removed $plist"
    fi
  done
fi

# ── 3. Remove plugin symlink ──
echo "[2/6] Removing plugin link..."

if [ -L "$PLUGIN_LINK" ] || [ -d "$PLUGIN_LINK" ]; then
  rm -rf "$PLUGIN_LINK"
  echo "  Removed $PLUGIN_LINK"
else
  echo "  No plugin link found."
fi

# ── 4. Remove kyaclaw-security from plugins.allow ──
echo "[3/6] Cleaning openclaw.json..."

if [ -f "$OPENCLAW_JSON" ] && grep -q "kyaclaw-security" "$OPENCLAW_JSON" 2>/dev/null; then
  BACKUP="${OPENCLAW_JSON}.backup.$(date +%Y%m%d_%H%M%S)"
  cp "$OPENCLAW_JSON" "$BACKUP"
  echo "  Backed up openclaw.json to $BACKUP"
  node -e "
    const fs = require('fs');
    const cfg = JSON.parse(fs.readFileSync('$OPENCLAW_JSON', 'utf8'));
    if (cfg.plugins && Array.isArray(cfg.plugins.allow)) {
      cfg.plugins.allow = cfg.plugins.allow.filter(p => p !== 'kyaclaw-security');
      if (cfg.plugins.allow.length === 0) delete cfg.plugins.allow;
      fs.writeFileSync('$OPENCLAW_JSON', JSON.stringify(cfg, null, 2) + '\n');
      process.stdout.write('  Removed kyaclaw-security from plugins.allow\n');
    }
  "
else
  echo "  No kyaclaw-security found in openclaw.json"
fi

# ── 5. Remove audit logs and security data ──
echo "[4/6] Removing security data..."

if [ -d "$SECURITY_DIR" ]; then
  read -rp "  Delete audit logs in $SECURITY_DIR? [y/N] " del_audit
  if [[ "$del_audit" =~ ^[Yy]$ ]]; then
    rm -rf "$SECURITY_DIR"
    echo "  Removed $SECURITY_DIR"
  else
    echo "  Kept $SECURITY_DIR"
  fi
else
  echo "  No security data found."
fi

# ── 6. Remove installation directory ──
echo "[5/6] Removing installation..."

if [ -d "$INSTALL_DIR" ]; then
  sudo rm -rf "$INSTALL_DIR"
  echo "  Removed $INSTALL_DIR"
else
  echo "  No installation found at $INSTALL_DIR"
fi

# ── 7. Kill any remaining processes ──
echo "[6/6] Cleaning up processes..."

for pattern in "kyaclaw-scanner" "kyaclaw-proxy" "kyaclaw-monitor" "KYACLAW_SCANNER_START" "KYACLAW_PROXY_START" "KYACLAW_MONITOR_START"; do
  pids=$(pgrep -f "$pattern" 2>/dev/null || true)
  if [ -n "$pids" ]; then
    echo "  Killing remaining processes: $pids"
    kill $pids 2>/dev/null || true
  fi
done

echo ""
echo "════════════════════════════════════════"
echo "  KyaClaw PRISM uninstalled."
echo "════════════════════════════════════════"

# ── Restart OpenClaw gateway ──
echo ""
read -rp "Restart OpenClaw gateway to unload the plugin? [y/N] " restart_gw
if [[ "$restart_gw" =~ ^[Yy]$ ]]; then
  RESTARTED=false
  for svc_name in openclaw openclaw-gateway; do
    if command -v systemctl &>/dev/null && systemctl is-active --quiet "$svc_name" 2>/dev/null; then
      sudo systemctl restart "$svc_name"
      echo "  OpenClaw gateway restarted (systemd: $svc_name)."
      RESTARTED=true
      break
    fi
  done
  if [ "$RESTARTED" = false ] && command -v pm2 &>/dev/null; then
    PM2_NAME=$(pm2 jlist 2>/dev/null | node -e "try{const d=JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));const p=d.find(x=>x.name.match(/openclaw|gateway/i));if(p)console.log(p.name)}catch{}" 2>/dev/null)
    if [ -n "$PM2_NAME" ]; then
      pm2 restart "$PM2_NAME"
      echo "  OpenClaw gateway restarted (pm2: $PM2_NAME)."
      RESTARTED=true
    fi
  fi
  if [ "$RESTARTED" = false ]; then
    GW_PID=$(pgrep -f "openclaw-gateway" 2>/dev/null | head -1)
    if [ -n "$GW_PID" ]; then
      GW_CMD=$(tr '\0' ' ' < /proc/$GW_PID/cmdline 2>/dev/null || echo "")
      GW_CWD=$(readlink /proc/$GW_PID/cwd 2>/dev/null || echo "")
      kill "$GW_PID" 2>/dev/null || true
      sleep 2
      if [ -n "$GW_CMD" ] && [ -n "$GW_CWD" ]; then
        cd "$GW_CWD" && nohup $GW_CMD > /dev/null 2>&1 &
        echo "  OpenClaw gateway restarted (PID: $!)."
        RESTARTED=true
      else
        echo "  Stopped OpenClaw gateway (PID $GW_PID)."
        echo "  Could not auto-restart. Please start it manually."
      fi
    else
      echo "  OpenClaw gateway not found. Please restart it manually."
    fi
  fi
else
  echo "  Skipped. Remember to restart OpenClaw gateway to unload the plugin."
fi
