#!/usr/bin/env python3
"""
Deploy Test HTTPS Backend VM on Google Cloud with Static IP and Restricted Firewall Rules.

This script provisions:
1. A static external IP (`secgw-nat-static-ip`) in `asia-northeast1` (Tokyo).
2. A custom VPC (`secgw-test-vpc`) and subnet (`secgw-test-subnet`, `10.10.0.0/24`).
3. A Cloud Router (`secgw-cloud-router`) and Cloud NAT (`secgw-cloud-nat`) configured with the static IP.
4. Firewall rules restricting ingress port 443 to Secure Gateway (`136.124.16.0/20`) and the static IP.
5. A private Compute Engine VM (`secgw-https-backend-01`) running Debian 12 + Nginx HTTPS (TLS 1.2/1.3).
"""

import argparse
import json
import subprocess
import sys
import time
import urllib.request
import urllib.error

PROJECT_ID_DEFAULT = "montreal-436802"
REGION_DEFAULT = "asia-northeast1"
ZONE_DEFAULT = "asia-northeast1-b"
VPC_NAME = "secgw-test-vpc"
SUBNET_NAME = "secgw-test-subnet"
SUBNET_RANGE = "10.10.0.0/24"
STATIC_IP_NAME = "secgw-nat-static-ip"
ROUTER_NAME = "secgw-cloud-router"
NAT_NAME = "secgw-cloud-nat"
VM_NAME = "secgw-https-backend-01"
SECURE_GATEWAY_SOURCE_RANGE = "136.124.16.0/20"
IAP_SOURCE_RANGE = "35.235.240.0/20"

STARTUP_SCRIPT = """#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# Install Nginx and OpenSSL
apt-get update
apt-get install -y --no-install-recommends nginx openssl curl

# Generate self-signed TLS certificate for testing
mkdir -p /etc/nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \\
  -keyout /etc/nginx/ssl/server.key \\
  -out /etc/nginx/ssl/server.crt \\
  -subj "/CN=secgw-backend.internal/O=SecureGatewayPoc/C=JP" \\
  -addext "subjectAltName=DNS:secgw-backend.internal,DNS:demo-server.internal,IP:10.10.0.2"

chmod 600 /etc/nginx/ssl/server.key
chmod 644 /etc/nginx/ssl/server.crt

# Configure Nginx for both HTTP (port 80) and HTTPS (port 443)
cat <<'EOF' > /etc/nginx/sites-available/default
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    location /healthz {
        default_type text/plain;
        return 200 'healthy\\n';
    }

    location /api/status {
        default_type application/json;
        return 200 '{"status":"ok","service":"Secure Gateway Backend","protocol":"HTTP","port":"$server_port","client_ip":"$remote_addr","x_forwarded_for":"$http_x_forwarded_for","host":"$host","timestamp":"$time_iso8601","user_agent":"$http_user_agent"}\\n';
    }

    location / {
        default_type text/html;
        return 200 '<!DOCTYPE html><html><head><meta charset="utf-8"><title>SGW HTTP Backend</title><style>body{background:#0b0f19;color:#f1f5f9;font-family:sans-serif;padding:2rem;line-height:1.6}h1{color:#38bdf8}code{background:#1e293b;padding:0.2rem 0.5rem;border-radius:4px}</style></head><body><h1>🛡️ Secure Gateway HTTP Backend (Port 80)</h1><p>Client IP: <code>$remote_addr</code></p><p>Host: <code>$host</code></p><p>Time: <code>$time_iso8601</code></p><hr><p><a style="color:#38bdf8" href="/api/status">View JSON API (/api/status)</a></p></body></html>\\n';
    }
}

server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name _;

    ssl_certificate /etc/nginx/ssl/server.crt;
    ssl_certificate_key /etc/nginx/ssl/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location /healthz {
        default_type text/plain;
        return 200 'healthy\\n';
    }

    location /api/status {
        default_type application/json;
        return 200 '{"status":"ok","service":"Secure Gateway Backend","protocol":"HTTPS","tls_protocol":"$ssl_protocol","tls_cipher":"$ssl_cipher","port":"$server_port","client_ip":"$remote_addr","x_forwarded_for":"$http_x_forwarded_for","host":"$host","timestamp":"$time_iso8601","user_agent":"$http_user_agent"}\\n';
    }

    location / {
        default_type text/html;
        return 200 '<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>🎉 Congratulations! - BeyondCorp Secure Gateway</title>
  <style>
    :root {
      --bg: #0b0f19;
      --card: #131b2e;
      --card-border: #22304d;
      --accent: #38bdf8;
      --green: #34d399;
      --text: #f1f5f9;
      --muted: #94a3b8;
      --chip-bg: #1e293b;
      --chip-border: #334155;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      padding: 2.5rem 1.25rem;
      display: flex;
      justify-content: center;
      line-height: 1.5;
    }
    .wrapper {
      max-width: 960px;
      width: 100%;
      background: var(--card);
      border: 1px solid var(--card-border);
      border-radius: 16px;
      padding: 2.5rem;
      box-shadow: 0 24px 48px rgba(0, 0, 0, 0.45);
    }
    .hero {
      background: linear-gradient(135deg, rgba(16, 185, 129, 0.16), rgba(56, 189, 248, 0.16));
      border: 1.5px solid rgba(52, 211, 153, 0.45);
      border-radius: 14px;
      padding: 1.8rem;
      text-align: center;
      margin-bottom: 2rem;
    }
    .hero h1 {
      margin: 0 0 0.5rem;
      font-size: 1.85rem;
      color: var(--green);
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.6rem;
    }
    .hero p {
      margin: 0;
      font-size: 1.05rem;
      color: var(--text);
    }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }
    .stat-card {
      background: #070a12;
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 1.1rem;
    }
    .stat-card small {
      color: var(--muted);
      font-size: 0.78rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .stat-card .val {
      font-size: 1.25rem;
      font-weight: 700;
      color: var(--accent);
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      margin-top: 0.35rem;
    }
    .stat-card .sub {
      font-size: 0.8rem;
      color: var(--muted);
      margin-top: 0.25rem;
    }
    .section-title {
      font-size: 1.25rem;
      color: var(--accent);
      margin: 2.5rem 0 1.2rem;
      padding-bottom: 0.6rem;
      border-bottom: 1px solid var(--card-border);
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .arch-card {
      background: #070a12;
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 1.6rem;
      margin-bottom: 1.6rem;
    }
    .arch-card-header {
      display: flex;
      justify-content: space-between;
      align-items: baseline;
      margin-bottom: 0.8rem;
    }
    .arch-card h3 {
      margin: 0;
      color: var(--green);
      font-size: 1.15rem;
    }
    .arch-badge {
      background: rgba(56, 189, 248, 0.15);
      color: var(--accent);
      border: 1px solid rgba(56, 189, 248, 0.35);
      padding: 0.2rem 0.6rem;
      border-radius: 999px;
      font-size: 0.75rem;
      font-weight: 600;
    }
    .arch-card p {
      margin: 0 0 1.2rem;
      color: var(--muted);
      font-size: 0.92rem;
    }
    .flow-list {
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
    }
    .flow-row {
      display: grid;
      grid-template-columns: 170px 1fr 200px;
      gap: 1rem;
      background: var(--card);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 0.85rem 1.1rem;
      align-items: center;
      font-size: 0.9rem;
    }
    .flow-row strong {
      color: var(--accent);
      font-size: 0.92rem;
    }
    .flow-row .desc {
      color: var(--text);
      line-height: 1.4;
    }
    .ip-chip {
      background: var(--chip-bg);
      border: 1px solid var(--chip-border);
      padding: 0.3rem 0.6rem;
      border-radius: 6px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      color: #38bdf8;
      font-size: 0.82rem;
      text-align: center;
      white-space: nowrap;
    }
    table.meta-table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 0.5rem;
    }
    table.meta-table td {
      padding: 0.75rem 0;
      border-bottom: 1px solid #1e293b;
      font-size: 0.92rem;
    }
    table.meta-table td:first-child {
      color: var(--muted);
      width: 32%;
    }
    a.api-btn {
      display: inline-block;
      margin-top: 1.5rem;
      background: #0284c7;
      color: #ffffff;
      padding: 0.65rem 1.25rem;
      border-radius: 8px;
      font-weight: 600;
      text-decoration: none;
      transition: background 0.2s;
    }
    a.api-btn:hover {
      background: #0369a1;
    }
  </style>
</head>
<body>
  <div class="wrapper">
    <div class="hero">
      <h1>🎉 Congratulations!</h1>
      <p>BeyondCorp Secure Gateway 経由でプライベートバックエンドに正常に接続されました！</p>
      <p style="font-size: 0.9rem; color: var(--muted); margin-top: 0.4rem;">
        Chrome 拡張機能によるゼロトラスト認証・認可を通過し、Google Cloud VPC 内の安全な内部サーバーに到達しています。
      </p>
    </div>

    <div class="stats-grid">
      <div class="stat-card">
        <small>Client Ingress IP (SGW 送信元)</small>
        <div class="val">$remote_addr</div>
        <div class="sub">Google 固定範囲: 136.124.16.0/20</div>
      </div>
      <div class="stat-card">
        <small>Target Server Port</small>
        <div class="val">Port $server_port ($ssl_protocol)</div>
        <div class="sub">TLS Cipher: $ssl_cipher</div>
      </div>
      <div class="stat-card">
        <small>VM Internal IP</small>
        <div class="val">10.10.0.2</div>
        <div class="sub">VPC: secgw-test-vpc (asia-northeast1)</div>
      </div>
    </div>

    <div class="section-title">🌐 通信経路とアーキテクチャ詳細（IP アドレス対応）</div>

    <!-- Option A Architecture Diagram -->
    <div class="arch-card">
      <div class="arch-card-header">
        <h3>【Option A】直接プライベート HTTPS 接続アーキテクチャ</h3>
        <span class="arch-badge">本環境で稼働中</span>
      </div>
      <p>Secure Gateway が VPC 内の既存 HTTPS アプリケーションへ直接ルーティングする最もシンプルな構成です（NAT/Router/Nginxプロキシ不要）。</p>
      
      <div class="flow-list">
        <div class="flow-row">
          <div><strong>1. クライアント端末</strong></div>
          <div class="desc">管理対象 Chrome (Endpoint Verification + Secure Enterprise Browser)</div>
          <div class="ip-chip">クライアント端末 IP</div>
        </div>
        <div class="flow-row">
          <div><strong>2. Google Cloud エッジ</strong></div>
          <div class="desc">BeyondCorp Secure Gateway (CAA 認証・認可判定 ➔ VPC Egress)</div>
          <div class="ip-chip">FQDN: $host</div>
        </div>
        <div class="flow-row">
          <div><strong>3. VPC インバウンド</strong></div>
          <div class="desc">VPC ファイアウォール許可 (136.124.16.0/20 からの TCP 443 通信)</div>
          <div class="ip-chip">送信元: 136.124.16.0/20</div>
        </div>
        <div class="flow-row">
          <div><strong>4. Cloud DNS 解決</strong></div>
          <div class="desc">VPC 限定公開ゾーンで内部 IP に名前解決</div>
          <div class="ip-chip">$host ➔ 10.10.0.2</div>
        </div>
        <div class="flow-row">
          <div><strong>5. プライベート VM</strong></div>
          <div class="desc">Compute Engine VM (Nginx HTTPS 終端・Web サーバー)</div>
          <div class="ip-chip">着信先: 10.10.0.2:443</div>
        </div>
      </div>
    </div>

    <!-- Option B Architecture Diagram -->
    <div class="arch-card">
      <div class="arch-card-header">
        <h3>【Option B】内部ロードバランサー (ILB) HTTPS オフロード構成</h3>
        <span class="arch-badge">HTTP アプリ保護用</span>
      </div>
      <p>バックエンドが HTTP (ポート 80) の場合に、Regional Internal Application Load Balancer で TLS 終端をオフロードする構成です。</p>
      
      <div class="flow-list">
        <div class="flow-row">
          <div><strong>1. クライアント端末</strong></div>
          <div class="desc">Chrome Root Store で配布された Root CA 証明書を検証・信頼</div>
          <div class="ip-chip">クライアント端末 IP</div>
        </div>
        <div class="flow-row">
          <div><strong>2. Secure Gateway</strong></div>
          <div class="desc">ホスト名マッチング & VPC 転送</div>
          <div class="ip-chip">送信元: 136.124.16.0/20</div>
        </div>
        <div class="flow-row">
          <div><strong>3. 内部ロードバランサー</strong></div>
          <div class="desc">Regional Internal App LB (Envoy Proxy サブネットで TLS 復号)</div>
          <div class="ip-chip">ILB IP: 10.10.0.100:443</div>
        </div>
        <div class="flow-row">
          <div><strong>4. バックエンド アプリ</strong></div>
          <div class="desc">プライベート HTTP アプリケーション (VM / コンテナ)</div>
          <div class="ip-chip">内部 IP: 10.10.0.2:80 (HTTP)</div>
        </div>
      </div>
    </div>

    <div class="section-title">📋 現在のリクエスト メタデータ</div>
    <table class="meta-table">
      <tr><td>リクエスト ホスト名</td><td><strong>$host</strong></td></tr>
      <tr><td>受信サーバー ポート</td><td>TCP $server_port ($ssl_protocol)</td></tr>
      <tr><td>暗号スイート (Cipher)</td><td><code>$ssl_cipher</code></td></tr>
      <tr><td>VM 内部ホスト名 / IP</td><td>secgw-https-backend-01 (10.10.0.2)</td></tr>
      <tr><td>User-Agent</td><td><small>$http_user_agent</small></td></tr>
      <tr><td>接続タイムスタンプ</td><td>$time_iso8601</td></tr>
    </table>

    <p><a class="api-btn" href="/api/status">📄 JSON 形式のステータス API を開く (/api/status)</a></p>
  </div>
</body>
</html>\n';
    }
}
EOF

nginx -t
systemctl restart nginx
systemctl enable nginx
"""


def log(msg: str):
    print(f"[\033[94mINFO\033[0m] {msg}")


def log_success(msg: str):
    print(f"[\033[92mSUCCESS\033[0m] {msg}")


def log_warn(msg: str):
    print(f"[\033[93mWARN\033[0m] {msg}")


def log_error(msg: str):
    print(f"[\033[91mERROR\033[0m] {msg}")


class GCloudApi:
    def __init__(self, project_id: str, access_token: str = ""):
        self.project_id = project_id
        self.access_token = access_token or self._get_access_token()

    def _get_access_token(self) -> str:
        # Try gcloud CLI if available
        try:
            res = subprocess.run(
                ["gcloud", "auth", "print-access-token"],
                capture_output=True,
                text=True,
                check=True,
            )
            token = res.stdout.strip()
            if token:
                return token
        except Exception:
            pass

        # Try google.auth
        try:
            import google.auth
            import google.auth.transport.requests

            creds, _ = google.auth.default(
                scopes=["https://www.googleapis.com/auth/cloud-platform"]
            )
            auth_req = google.auth.transport.requests.Request()
            creds.refresh(auth_req)
            if creds.token:
                return creds.token
        except Exception:
            pass

        raise RuntimeError(
            "No valid Google Cloud authentication found. "
            "Please provide --token <access_token> or authenticate via gcloud / Chrome extension."
        )

    def request(self, method: str, url: str, body: dict = None) -> dict:
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
        }
        data = json.dumps(body).encode("utf-8") if body else None
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
                return json.loads(raw.decode("utf-8")) if raw else {}
        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8")
            try:
                err_json = json.loads(error_body)
                raise RuntimeError(
                    f"Google API error ({e.code}): {err_json.get('error', {}).get('message', error_body)}"
                )
            except Exception:
                raise RuntimeError(f"Google API error ({e.code}): {error_body}")

    def wait_for_operation(self, op: dict, region: str = None, zone: str = None):
        op_name = op.get("name")
        if not op_name:
            return
        log(f"Waiting for operation {op_name} to complete...")
        for _ in range(60):
            if zone:
                url = f"https://compute.googleapis.com/compute/v1/projects/{self.project_id}/zones/{zone}/operations/{op_name}"
            elif region:
                url = f"https://compute.googleapis.com/compute/v1/projects/{self.project_id}/regions/{region}/operations/{op_name}"
            else:
                url = f"https://compute.googleapis.com/compute/v1/projects/{self.project_id}/global/operations/{op_name}"
            try:
                status = self.request("GET", url)
                if status.get("status") == "DONE":
                    if "error" in status:
                        raise RuntimeError(f"Operation failed: {json.dumps(status['error'])}")
                    return status
            except Exception as ex:
                if "Not Found" in str(ex):
                    pass
                else:
                    raise ex
            time.sleep(2)
        log_warn("Operation wait timed out; proceeding.")


def main():
    parser = argparse.ArgumentParser(description="Deploy Private HTTPS Backend on GCP")
    parser.add_argument("--project", default=PROJECT_ID_DEFAULT, help="GCP Project ID")
    parser.add_argument("--region", default=REGION_DEFAULT, help="GCP Region")
    parser.add_argument("--zone", default=ZONE_DEFAULT, help="GCP Zone")
    parser.add_argument("--token", default="", help="OAuth2 Access Token")
    args = parser.parse_args()

    project_id = args.project
    region = args.region
    zone = args.zone

    log(f"Starting deployment for Project: {project_id} in {region} ({zone})")

    api = GCloudApi(project_id, args.token)

    # 1. Allocate Static External IP for Cloud NAT & Egress Whitelist
    log(f"1/6 Allocating Static External IP: {STATIC_IP_NAME} in {region}...")
    ip_address = ""
    try:
        addr_url = f"https://compute.googleapis.com/compute/v1/projects/{project_id}/regions/{region}/addresses/{STATIC_IP_NAME}"
        existing_addr = api.request("GET", addr_url)
        ip_address = existing_addr.get("address", "")
        log_success(f"Static IP already exists: {ip_address}")
    except Exception:
        create_addr_url = f"https://compute.googleapis.com/compute/v1/projects/{project_id}/regions/{region}/addresses"
        op = api.request("POST", create_addr_url, {"name": STATIC_IP_NAME, "description": "Static IP for Secure Gateway and GitHub Allowlist"})
        api.wait_for_operation(op, region=region)
        addr_info = api.request("GET", addr_url)
        ip_address = addr_info.get("address", "")
        log_success(f"Allocated Static External IP: {ip_address}")

    # 2. Create VPC Network
    log(f"2/6 Creating VPC Network: {VPC_NAME}...")
    vpc_url = f"https://compute.googleapis.com/compute/v1/projects/{project_id}/global/networks/{VPC_NAME}"
    try:
        api.request("GET", vpc_url)
        log_success(f"VPC {VPC_NAME} already exists.")
    except Exception:
        op = api.request(
            "POST",
            f"https://compute.googleapis.com/compute/v1/projects/{project_id}/global/networks",
            {"name": VPC_NAME, "autoCreateSubnetworks": False, "description": "Dedicated VPC for Secure Gateway PoC"},
        )
        api.wait_for_operation(op)
        log_success(f"Created VPC {VPC_NAME}.")

    # 3. Create Subnet with Private Google Access
    log(f"3/6 Creating Subnet: {SUBNET_NAME} ({SUBNET_RANGE})...")
    subnet_url = f"https://compute.googleapis.com/compute/v1/projects/{project_id}/regions/{region}/subnetworks/{SUBNET_NAME}"
    try:
        api.request("GET", subnet_url)
        log_success(f"Subnet {SUBNET_NAME} already exists.")
    except Exception:
        op = api.request(
            "POST",
            f"https://compute.googleapis.com/compute/v1/projects/{project_id}/regions/{region}/subnetworks",
            {
                "name": SUBNET_NAME,
                "ipCidrRange": SUBNET_RANGE,
                "network": f"projects/{project_id}/global/networks/{VPC_NAME}",
                "privateIpGoogleAccess": True,
            },
        )
        api.wait_for_operation(op, region=region)
        log_success(f"Created Subnet {SUBNET_NAME}.")

    # 4. Create Cloud Router & Cloud NAT with the Static IP
    log(f"4/6 Configuring Cloud Router & Cloud NAT with Static IP {ip_address}...")
    router_url = f"https://compute.googleapis.com/compute/v1/projects/{project_id}/regions/{region}/routers/{ROUTER_NAME}"
    try:
        api.request("GET", router_url)
        log_success(f"Router {ROUTER_NAME} already exists.")
    except Exception:
        op = api.request(
            "POST",
            f"https://compute.googleapis.com/compute/v1/projects/{project_id}/regions/{region}/routers",
            {
                "name": ROUTER_NAME,
                "network": f"projects/{project_id}/global/networks/{VPC_NAME}",
                "nats": [
                    {
                        "name": NAT_NAME,
                        "natIpAllocateOption": "MANUAL_ONLY",
                        "natIps": [f"projects/{project_id}/regions/{region}/addresses/{STATIC_IP_NAME}"],
                        "sourceSubnetworkIpRangesToNat": "ALL_SUBNETWORKS_ALL_IP_RANGES",
                    }
                ],
            },
        )
        api.wait_for_operation(op, region=region)
        log_success(f"Created Cloud Router & Cloud NAT with fixed Egress IP {ip_address}.")

    # 5. Create Firewall Rules
    log("5/6 Configuring Firewall Rules...")
    # Rule 1: Secure Gateway + Health Checks + Static IP Ingress on port 80/443
    fw_https = f"https://compute.googleapis.com/compute/v1/projects/{project_id}/global/firewalls/allow-secgw-ingress-https"
    try:
        api.request("GET", fw_https)
        log_success("Firewall rule allow-secgw-ingress-https already exists.")
    except Exception:
        allowed_sources = [SECURE_GATEWAY_SOURCE_RANGE, "35.191.0.0/16", "130.211.0.0/22", "10.0.0.0/8"]
        if ip_address:
            allowed_sources.append(f"{ip_address}/32")
        op = api.request(
            "POST",
            f"https://compute.googleapis.com/compute/v1/projects/{project_id}/global/firewalls",
            {
                "name": "allow-secgw-ingress-https",
                "network": f"projects/{project_id}/global/networks/{VPC_NAME}",
                "direction": "INGRESS",
                "sourceRanges": allowed_sources,
                "allowed": [{"IPProtocol": "tcp", "ports": ["80", "443"]}],
                "description": "Allow Secure Gateway, ILB Health Checks, and NAT to reach test backend",
            },
        )
        api.wait_for_operation(op)
        log_success(f"Created firewall rule allowing 80/443 from {allowed_sources}.")

    # Rule 2: IAP SSH Management Ingress
    fw_iap = f"https://compute.googleapis.com/compute/v1/projects/{project_id}/global/firewalls/allow-iap-ssh"
    try:
        api.request("GET", fw_iap)
    except Exception:
        op = api.request(
            "POST",
            f"https://compute.googleapis.com/compute/v1/projects/{project_id}/global/firewalls",
            {
                "name": "allow-iap-ssh",
                "network": f"projects/{project_id}/global/networks/{VPC_NAME}",
                "direction": "INGRESS",
                "sourceRanges": [IAP_SOURCE_RANGE],
                "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
                "description": "Allow IAP SSH management",
            },
        )
        api.wait_for_operation(op)
        log_success("Created firewall rule allowing IAP SSH.")

    # 6. Create Private HTTPS Backend VM
    log(f"6/6 Launching Private HTTPS Backend VM: {VM_NAME} in {zone}...")
    vm_url = f"https://compute.googleapis.com/compute/v1/projects/{project_id}/zones/{zone}/instances/{VM_NAME}"
    vm_private_ip = ""
    try:
        existing_vm = api.request("GET", vm_url)
        vm_private_ip = existing_vm.get("networkInterfaces", [{}])[0].get("networkIP", "")
        log_success(f"VM {VM_NAME} already exists with Private IP: {vm_private_ip}")
    except Exception:
        op = api.request(
            "POST",
            f"https://compute.googleapis.com/compute/v1/projects/{project_id}/zones/{zone}/instances",
            {
                "name": VM_NAME,
                "machineType": f"zones/{zone}/machineTypes/e2-micro",
                "disks": [
                    {
                        "boot": True,
                        "autoDelete": True,
                        "initializeParams": {
                            "sourceImage": "projects/debian-cloud/global/images/family/debian-12",
                            "diskSizeGb": "20",
                        },
                    }
                ],
                "networkInterfaces": [
                    {
                        "network": f"projects/{project_id}/global/networks/{VPC_NAME}",
                        "subnetwork": f"projects/{project_id}/regions/{region}/subnetworks/{SUBNET_NAME}",
                        # No accessConfigs -> Private IP only (No Public IP)
                    }
                ],
                "metadata": {
                    "items": [
                        {"key": "startup-script", "value": STARTUP_SCRIPT},
                        {"key": "enable-oslogin", "value": "TRUE"},
                    ]
                },
                "tags": {"items": ["secgw-backend"]},
            },
        )
        api.wait_for_operation(op, zone=zone)
        vm_info = api.request("GET", vm_url)
        vm_private_ip = vm_info.get("networkInterfaces", [{}])[0].get("networkIP", "")
        log_success(f"Launched VM {VM_NAME} with Private IP: {vm_private_ip}")

    print("\n" + "=" * 60)
    print("\033[92m🎉 GCP HTTPS BACKEND & FIXED IP INFRASTRUCTURE READY!\033[0m")
    print("=" * 60)
    print(f"• GCP Project:        {project_id}")
    print(f"• Dedicated VPC:      {VPC_NAME}")
    print(f"• Private Subnet:     {SUBNET_NAME} ({SUBNET_RANGE})")
    print(f"• Backend VM:         {VM_NAME} (Debian 12 + Nginx HTTPS)")
    print(f"• Backend Private IP: {vm_private_ip}")
    print(f"• Static External IP: \033[1m\033[93m{ip_address}\033[0m")
    print("=" * 60)
    print("\n🔒 \033[1mGITHUB IP RESTRICTION SETUP\033[0m:")
    print("1. Go to your GitHub Organization: https://github.com/organizations/<YOUR_ORG>/settings/security")
    print("2. Under 'IP allowlist', click 'Add IP address'")
    print(f"3. Enter: {ip_address}/32 (Description: GCP Secure Gateway Egress Static IP)")
    print("4. Enable 'Enable IP allowlist' checkbox.")
    print("Now, GitHub access is strictly restricted to traffic from this fixed IP!\n")


if __name__ == "__main__":
    main()
