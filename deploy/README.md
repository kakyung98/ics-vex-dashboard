# Deploying the L0+L3 analyzer on a lab server

The public GitHub Pages site is static, so its analyzer runs in the browser against
the small 42-entry OSS KB. To run the **L0+L3** matcher (the full NVD CPE index,
13,764 products — so ICS products like Sielco Winlog resolve) the app needs a
backend that holds the 18 MB index in memory. This directory sets that up.

The server hosts **UI + API from one origin**, so there is no HTTPS/mixed-content
issue and no CORS. Users open `http://<server-ip>:<port>/` directly.

## Read this first — security

The server is exposed on the network, so before deploying:

- **Change the account password to a strong one**, and prefer **SSH key auth with
  password login disabled** (`PasswordAuthentication no` in `sshd_config`). A public
  IP with a weak password is compromised within hours.
- Only open the app port to the networks that need it (campus/VPN), not the whole
  internet, unless that is intended: `sudo ufw allow from <cidr> to any port <port>`.
- This app serves public advisory data and runs no PoC, but it is research code —
  keep it behind the firewall you would give any internal tool.

## Steps (run on the server, after you SSH in)

```bash
# 1. get a free NVD API key once: https://nvd.nist.gov/developers/request-an-api-key
export NVD_API_KEY=your-key-here

# 2. fetch and run the setup (clones the repo, installs deps, builds the 18MB index)
curl -fsSL https://raw.githubusercontent.com/kakyung98/ics-vex-dashboard/main/deploy/setup_server.sh -o setup_server.sh
bash setup_server.sh
```

`setup_server.sh` prints the exact commands to start the server (foreground test) or
install it as a `systemd` service, plus the firewall hint. Defaults: dir
`~/ics-vex-dashboard`, port `8100` (override with `ICSVEX_DIR` / `ICSVEX_PORT`).

## What runs

- `src/api_server.py` — FastAPI app (`app` is module-level). `/api/vex` now runs the
  42-KB pass **and** the L0+L3 pass; L0-identified CVEs are tagged
  `identified_by: "l0-…"` with the vendor-confidence grade in `identified_detail`.
- `data/cpe_index.json` — built on the server by `tools/build_cpe_index.py`; not in
  the repo (18 MB, regenerable). Delete it and re-run to refresh from NVD.

## Update later

```bash
cd ~/ics-vex-dashboard && git pull && sudo systemctl restart ics-vex
```
