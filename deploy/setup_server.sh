#!/usr/bin/env bash
# ICS-VEX L0+L3 analyzer — lab-server setup. Run this AFTER you SSH into the server.
#
# The server hosts BOTH the UI and the API from one origin (http://<server-ip>:PORT/),
# so there is no HTTPS/mixed-content problem and no CORS to configure. The analyzer
# then identifies CVEs with the full NVD CPE index (13,764 products) instead of the
# 42-entry OSS KB.
#
# Prereqs on the server: git, python3.10+ (PEP 604 type hints), and — only for the
# first run — an NVD API key exported as NVD_API_KEY (free:
# https://nvd.nist.gov/developers/request-an-api-key).
#
# Usage:
#   export NVD_API_KEY=your-key-here
#   bash deploy/setup_server.sh            # clone/update, install, build index, print run cmds
#
# Override defaults with env vars: ICSVEX_DIR, ICSVEX_PORT, ICSVEX_REPO.
set -euo pipefail

REPO="${ICSVEX_REPO:-https://github.com/kakyung98/ics-vex-dashboard.git}"
DIR="${ICSVEX_DIR:-$HOME/ics-vex-dashboard}"
PORT="${ICSVEX_PORT:-8100}"

echo "== 1/4 clone / update =="
if [ -d "$DIR/.git" ]; then git -C "$DIR" pull --ff-only; else git clone --depth 1 "$REPO" "$DIR"; fi
cd "$DIR"

echo "== 2/4 venv + deps =="
python3 -m venv .venv
# shellcheck disable=SC1091
. .venv/bin/activate
python -m pip install -q --upgrade pip
python -m pip install -q -r requirements.txt

echo "== 3/4 L0 CPE index (18MB, NOT in the repo) =="
if [ -f data/cpe_index.json ]; then
  echo "   data/cpe_index.json already present — skip (delete it to rebuild)"
else
  : "${NVD_API_KEY:?set NVD_API_KEY first: export NVD_API_KEY=xxxx  (free at https://nvd.nist.gov/developers/request-an-api-key)}"
  python tools/build_cpe_index.py   # ~2-3 min with a key
fi

echo "== 4/4 systemd unit (for persistence) =="
cat > /tmp/ics-vex.service <<EOF
[Unit]
Description=ICS-VEX L0+L3 analyzer
After=network.target

[Service]
User=$(id -un)
WorkingDirectory=$DIR
ExecStart=$DIR/.venv/bin/python $DIR/src/api_server.py --host 0.0.0.0 --port $PORT
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
echo "   wrote /tmp/ics-vex.service"

cat <<EOF

Setup done. Next:

  Quick test (foreground, Ctrl-C to stop):
    cd "$DIR" && .venv/bin/python src/api_server.py --host 0.0.0.0 --port $PORT

  Run persistently (needs sudo):
    sudo cp /tmp/ics-vex.service /etc/systemd/system/ics-vex.service
    sudo systemctl daemon-reload && sudo systemctl enable --now ics-vex
    systemctl status ics-vex --no-pager

  Open:  http://<server-ip>:$PORT/
  Firewall: allow the port if closed, e.g.  sudo ufw allow $PORT/tcp

  To update later:  cd "$DIR" && git pull && sudo systemctl restart ics-vex
EOF
