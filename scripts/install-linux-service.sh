#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 || $# -gt 5 ]]; then
  echo "Usage: sudo $0 <service-user> <proxy-url> <domains-file> [port] [binary]" >&2
  exit 2
fi

if [[ ${EUID} -ne 0 ]]; then
  echo "Run this installer as root (sudo)." >&2
  exit 1
fi

service_user=$1
proxy_url=$2
domains_file=$(realpath "$3")
port=${4:-12345}
binary=$(realpath "${5:-./target/release/selective-proxy}")
service_name=selective-proxy
unit_path="/etc/systemd/system/${service_name}.service"

if ! id "$service_user" >/dev/null 2>&1; then
  echo "Unknown service user: $service_user" >&2
  exit 1
fi
if [[ ! -x "$binary" ]]; then
  echo "Executable not found: $binary" >&2
  exit 1
fi
if [[ ! -r "$domains_file" ]]; then
  echo "Domains file is not readable: $domains_file" >&2
  exit 1
fi
if [[ "$proxy_url" == *$'\n'* || "$proxy_url" == *$'\r'* ]]; then
  echo "Proxy URL contains a newline." >&2
  exit 1
fi

cat >"$unit_path" <<EOF
[Unit]
Description=Selective HTTP/HTTPS proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=${binary} run --domains ${domains_file} --proxy ${proxy_url} --user ${service_user} --port ${port}
Restart=on-failure
RestartSec=3s
StartLimitIntervalSec=0
KillMode=control-group
TimeoutStopSec=15s

[Install]
WantedBy=multi-user.target
EOF

chmod 0644 "$unit_path"
systemctl daemon-reload
systemctl enable --now "$service_name.service"
systemctl --no-pager --full status "$service_name.service" || true

echo "Installed $unit_path"
echo "Logs: journalctl -u $service_name -f"
echo "Remove: sudo systemctl disable --now $service_name && sudo rm $unit_path && sudo systemctl daemon-reload"
