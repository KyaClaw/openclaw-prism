#!/usr/bin/env bash
set -euo pipefail

# ── KyaClaw PRISM Installer ──
# Run on the OpenClaw server: bash install.sh (do NOT run with sudo)

# Resolve real user home even if run via sudo
if [ -n "${SUDO_USER:-}" ]; then
  REAL_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
else
  REAL_HOME="$HOME"
fi

INSTALL_DIR="/opt/openclaw-prism"
OPENCLAW_DIR="$REAL_HOME/.openclaw"
OPENCLAW_JSON="$OPENCLAW_DIR/openclaw.json"
EXTENSIONS_DIR="$OPENCLAW_DIR/extensions"
SECURITY_DIR="$OPENCLAW_DIR/security"

echo "╔══════════════════════════════════════╗"
echo "║  KyaClaw PRISM Installer v0.1.0     ║"
echo "╚══════════════════════════════════════╝"
echo ""

# ── 1. Check prerequisites ──
echo "[1/7] Checking prerequisites..."

if ! command -v node &>/dev/null; then
  echo "ERROR: node not found. Install Node.js 22+ first."
  exit 1
fi

NODE_MAJOR=$(node -e "process.stdout.write(String(process.versions.node.split('.')[0]))")
if [ "$NODE_MAJOR" -lt 22 ]; then
  echo "ERROR: Node.js 22+ required, found v$(node -v)"
  exit 1
fi

if ! command -v pnpm &>/dev/null; then
  echo "Installing pnpm..."
  npm install -g pnpm
fi

echo "  node $(node -v), pnpm $(pnpm -v)"

# ── 2. Install to /opt ──
echo "[2/7] Installing to $INSTALL_DIR..."

if [ ! -d "$INSTALL_DIR" ]; then
  echo "  Creating $INSTALL_DIR..."
  sudo mkdir -p "$INSTALL_DIR"
  sudo chown "$(whoami)" "$INSTALL_DIR"
else
  echo "  Updating existing installation..."
fi

# Always sync source files (handles both fresh install and updates)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
rsync -a --exclude='openclaw/' --exclude='node_modules/' --exclude='.git/' --exclude='dist/' \
  "$SCRIPT_DIR/" "$INSTALL_DIR/"

cd "$INSTALL_DIR"

# ── 3. Install dependencies & build ──
echo "[3/7] Installing dependencies and building..."
pnpm install --frozen-lockfile 2>/dev/null || pnpm install
pnpm build

# ── 4. Generate secrets (first install only) ──
echo "[4/7] Setting up secrets..."

ENV_FILE="$INSTALL_DIR/.env"
if [ ! -f "$ENV_FILE" ]; then
  HMAC_KEY=$(openssl rand -hex 32)
  PROXY_TOKEN=$(openssl rand -hex 32)
  SCANNER_TOKEN=$(openssl rand -hex 32)

  # Auto-detect gateway token from openclaw.json
  GATEWAY_TOKEN=""
  if command -v node &>/dev/null && [ -f "$OPENCLAW_JSON" ]; then
    GATEWAY_TOKEN=$(node -e "try{const c=require('$OPENCLAW_JSON');console.log(c.gateway?.auth?.token||'')}catch{}" 2>/dev/null)
  fi
  if [ -z "$GATEWAY_TOKEN" ] && [ -n "${OPENCLAW_GATEWAY_TOKEN:-}" ]; then
    GATEWAY_TOKEN="$OPENCLAW_GATEWAY_TOKEN"
  fi

  if [ -n "$GATEWAY_TOKEN" ]; then
    echo "  Auto-detected gateway token from openclaw.json"
  else
    GATEWAY_TOKEN="change-me"
    echo "  WARNING: Could not detect gateway token."
    echo "  Update OPENCLAW_GATEWAY_TOKEN in $ENV_FILE after install."
  fi

  cat > "$ENV_FILE" <<EOF
# KyaClaw PRISM secrets — generated on $(date -Iseconds)
OPENCLAW_AUDIT_HMAC_KEY=$HMAC_KEY
OPENCLAW_GATEWAY_TOKEN=$GATEWAY_TOKEN

# Proxy client token (put this in your API client config)
KYACLAW_PROXY_CLIENT_TOKEN=$PROXY_TOKEN

# Scanner config
SCANNER_HOST=127.0.0.1
SCANNER_PORT=18766
SCANNER_AUTH_TOKEN=$SCANNER_TOKEN
OLLAMA_URL=http://127.0.0.1:11434/api/generate
OLLAMA_MODEL=qwen3:30b

# Proxy config
INVOKE_GUARD_POLICY=$INSTALL_DIR/config/invoke-guard.policy.json
EOF

  # Update policy with generated token
  sed -i "s/replace-with-long-random-token/$PROXY_TOKEN/" "$INSTALL_DIR/config/invoke-guard.policy.json" 2>/dev/null || \
  sed -i '' "s/replace-with-long-random-token/$PROXY_TOKEN/" "$INSTALL_DIR/config/invoke-guard.policy.json"

  echo "  Generated new secrets in $ENV_FILE"
else
  echo "  Secrets already exist."
  # Auto-fix gateway token if still placeholder
  if grep -q "change-me" "$ENV_FILE" 2>/dev/null; then
    GATEWAY_TOKEN=""
    if command -v node &>/dev/null && [ -f "$OPENCLAW_JSON" ]; then
      GATEWAY_TOKEN=$(node -e "try{const c=require('$OPENCLAW_JSON');console.log(c.gateway?.auth?.token||'')}catch{}" 2>/dev/null)
    fi
    if [ -z "$GATEWAY_TOKEN" ] && [ -n "${OPENCLAW_GATEWAY_TOKEN:-}" ]; then
      GATEWAY_TOKEN="$OPENCLAW_GATEWAY_TOKEN"
    fi
    if [ -n "$GATEWAY_TOKEN" ]; then
      sed -i "s|OPENCLAW_GATEWAY_TOKEN=.*|OPENCLAW_GATEWAY_TOKEN=$GATEWAY_TOKEN|" "$ENV_FILE"
      echo "  Auto-detected and updated gateway token."
    else
      echo "  WARNING: Gateway token still set to placeholder."
    fi
  fi
  if ! grep -q "^SCANNER_AUTH_TOKEN=" "$ENV_FILE" 2>/dev/null; then
    SCANNER_TOKEN=$(openssl rand -hex 32)
    echo "SCANNER_AUTH_TOKEN=$SCANNER_TOKEN" >> "$ENV_FILE"
    echo "  Added missing SCANNER_AUTH_TOKEN."
  fi
fi

# ── 5. Link plugin to OpenClaw extensions ──
echo "[5/7] Linking plugin to OpenClaw..."

mkdir -p "$EXTENSIONS_DIR"
PLUGIN_LINK="$EXTENSIONS_DIR/kyaclaw-security"

if [ -L "$PLUGIN_LINK" ] || [ -d "$PLUGIN_LINK" ]; then
  rm -rf "$PLUGIN_LINK"
fi
ln -s "$INSTALL_DIR/packages/plugin" "$PLUGIN_LINK"
echo "  Linked: $PLUGIN_LINK -> $INSTALL_DIR/packages/plugin"

# Add to OpenClaw plugins.allow if openclaw.json exists
if [ -f "$OPENCLAW_JSON" ]; then
  if ! grep -q "kyaclaw-security" "$OPENCLAW_JSON" 2>/dev/null; then
    BACKUP="${OPENCLAW_JSON}.backup.$(date +%Y%m%d_%H%M%S)"
    cp "$OPENCLAW_JSON" "$BACKUP"
    echo "  Backed up openclaw.json to $BACKUP"
    echo "  Adding kyaclaw-security to plugins.allow..."
    node -e "
      const fs = require('fs');
      const cfg = JSON.parse(fs.readFileSync('$OPENCLAW_JSON', 'utf8'));
      if (!cfg.plugins) cfg.plugins = {};
      if (!Array.isArray(cfg.plugins.allow)) cfg.plugins.allow = [];
      if (!cfg.plugins.allow.includes('kyaclaw-security')) {
        cfg.plugins.allow.push('kyaclaw-security');
        fs.writeFileSync('$OPENCLAW_JSON', JSON.stringify(cfg, null, 2) + '\n');
        process.stdout.write('  Added kyaclaw-security to plugins.allow\n');
      }
    "
  else
    echo "  kyaclaw-security already in plugins.allow"
  fi
else
  echo "  WARNING: $OPENCLAW_JSON not found, skipping plugins.allow"
fi

# ── 6. Install systemd services (Linux only) ──
echo "[6/7] Installing services..."

mkdir -p "$SECURITY_DIR"

if [ -d /etc/systemd/system ] && command -v systemctl &>/dev/null; then
  echo "  Installing systemd services..."

  RUN_USER="$(whoami)"
  for svc in kyaclaw-scanner kyaclaw-proxy kyaclaw-monitor; do
    sudo cp "$INSTALL_DIR/systemd/${svc}.service" /etc/systemd/system/
    # Replace user placeholder and inject environment file
    sudo sed -i "s/__KYACLAW_USER__/$RUN_USER/" "/etc/systemd/system/${svc}.service"
    sudo sed -i "/\[Service\]/a EnvironmentFile=$ENV_FILE" "/etc/systemd/system/${svc}.service" 2>/dev/null || true
  done

  sudo systemctl daemon-reload
  sudo systemctl enable kyaclaw-scanner kyaclaw-proxy kyaclaw-monitor
  sudo systemctl start kyaclaw-scanner kyaclaw-proxy kyaclaw-monitor

  echo "  Services started."

elif [ "$(uname)" = "Darwin" ]; then
  echo "  macOS detected. To install launchd services:"
  echo "    cp $INSTALL_DIR/launchd/*.plist ~/Library/LaunchAgents/"
  echo "    launchctl load ~/Library/LaunchAgents/com.kyaclaw.*.plist"
  echo ""
  echo "  Or run manually:"
  echo "    source $ENV_FILE && npx tsx $INSTALL_DIR/packages/scanner/src/index.ts &"
  echo "    source $ENV_FILE && npx tsx $INSTALL_DIR/packages/proxy/src/index.ts &"
  echo "    source $ENV_FILE && npx tsx $INSTALL_DIR/packages/monitor/src/index.ts &"

else
  echo "  No systemd found. Start services manually:"
  echo "    source $ENV_FILE"
  echo "    node $INSTALL_DIR/packages/scanner/dist/index.js &"
  echo "    node $INSTALL_DIR/packages/proxy/dist/index.js &"
  echo "    node $INSTALL_DIR/packages/monitor/dist/index.js &"
fi

# ── 7. Verify ──
echo "[7/7] Verifying installation..."
sleep 2

OK=true
for port_name in "18766:scanner" "18767:proxy"; do
  PORT="${port_name%%:*}"
  NAME="${port_name##*:}"
  if curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then
    echo "  ✓ $NAME (:$PORT) healthy"
  else
    echo "  ✗ $NAME (:$PORT) not responding (may need manual start)"
    OK=false
  fi
done

echo ""
echo "════════════════════════════════════════"
if [ "$OK" = true ]; then
  echo "  PRISM installed and running!"
else
  echo "  PRISM installed. Some services need manual start."
fi
echo ""
echo "  Config:   $INSTALL_DIR/config/"
echo "  Secrets:  $ENV_FILE"
echo "  Logs:     $SECURITY_DIR/audit.jsonl"
echo "  Plugin:   $PLUGIN_LINK"
echo ""
if grep -q "change-me" "$ENV_FILE" 2>/dev/null; then
  echo "  NOTE: Set OPENCLAW_GATEWAY_TOKEN in $ENV_FILE"
fi
echo "════════════════════════════════════════"

# ── 8. Restart OpenClaw gateway ──
echo ""
read -rp "Restart OpenClaw gateway now to load the plugin? [y/N] " restart_gw
if [[ "$restart_gw" =~ ^[Yy]$ ]]; then
  RESTARTED=false
  # Try systemd first
  for svc_name in openclaw openclaw-gateway; do
    if command -v systemctl &>/dev/null && systemctl is-active --quiet "$svc_name" 2>/dev/null; then
      sudo systemctl restart "$svc_name"
      echo "  OpenClaw gateway restarted (systemd: $svc_name)."
      RESTARTED=true
      break
    fi
  done
  # Try pm2
  if [ "$RESTARTED" = false ] && command -v pm2 &>/dev/null; then
    PM2_NAME=$(pm2 jlist 2>/dev/null | node -e "try{const d=JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));const p=d.find(x=>x.name.match(/openclaw|gateway/i));if(p)console.log(p.name)}catch{}" 2>/dev/null)
    if [ -n "$PM2_NAME" ]; then
      pm2 restart "$PM2_NAME"
      echo "  OpenClaw gateway restarted (pm2: $PM2_NAME)."
      RESTARTED=true
    fi
  fi
  # Try direct process (send SIGHUP to reload, or kill and let user restart)
  if [ "$RESTARTED" = false ]; then
    GW_PID=$(pgrep -f "openclaw-gateway" 2>/dev/null | head -1)
    if [ -n "$GW_PID" ]; then
      # Get the original command for restart
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
      echo "  OpenClaw gateway not found. Please start it manually."
    fi
  fi
else
  echo "  Skipped. Remember to restart OpenClaw gateway to load the plugin."
fi
