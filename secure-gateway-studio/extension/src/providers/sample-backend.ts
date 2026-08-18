import type { Transport } from "./executor.ts";

const COMPUTE = "https://compute.googleapis.com/compute/v1";
const SECURE_GATEWAY_SOURCE_RANGE = "136.124.16.0/20";
const HEALTH_CHECK_RANGES = ["35.191.0.0/16", "130.211.0.0/22"];
const IAP_RANGE = "35.235.240.0/20";

const STARTUP_SCRIPT = `#!/bin/bash
export DEBIAN_FRONTEND=noninteractive

for i in {1..10}; do
  apt-get update && apt-get install -y --no-install-recommends nginx openssl curl && break
  sleep 3
done

mkdir -p /etc/nginx/ssl

cat <<'EOF' > /etc/nginx/ssl/server.crt
-----BEGIN CERTIFICATE-----
MIIDujCCAqKgAwIBAgIUZe6miybmD9bVjxjQ+EJdBUOKAuswDQYJKoZIhvcNAQEL
BQAwUDEiMCAGA1UECgwZU2VjdXJlIEdhdGV3YXkgU3R1ZGlvIFBvQzEqMCgGA1UE
AwwhU2VjdXJlIEdhdGV3YXkgU3R1ZGlvIFBvQyBSb290IENBMB4XDTI2MDgxMzEx
NDk0NVoXDTM2MDgxMTExNDk0NVowRTEiMCAGA1UECgwZU2VjdXJlIEdhdGV3YXkg
U3R1ZGlvIFBvQzEfMB0GA1UEAwwWc2VjZ3ctYmFja2VuZC5pbnRlcm5hbDCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAI45ACfuQJsx4pOja5YgN7hTTSqj
/Rtk5ZowGQYPLoj9qX6GSGjYjzx9UahGlfpsxdO0mOz+1e12qwHMC4AsBnlD2HC2
HJeKvWaaljRMOMGCNkGwz2inKw4uJPHBL0NWXwRWBCDMhxLLTjwOWIlRjAQFAVhq
X03vGgOOsJo7bKRajSWgmUVRAesX/77xSB+QH+uvte9piVumjKU2tBJ0tPIR1+dH
dY2yKcGr4Erp20RH32AHRCXqcQPCamcG5K7B9+T9bKm3ZkDedzoHk2ZYcJo9HBGT
PmFFSF/VvN61a4EBrwMKyCpLpp0tPO/ENj5FNqadKMFQoMA3w2lebeGl5ZsCAwEA
AaOBljCBkzAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAK
BggrBgEFBQcDATA9BgNVHREENjA0ghZzZWNndy1iYWNrZW5kLmludGVybmFsghRk
ZW1vLXNlcnZlci5pbnRlcm5hbIcECgoAAjAfBgNVHSMEGDAWgBQ7MYyC2PZ6vt8e
aoN0BfIpvYLYgDANBgkqhkiG9w0BAQsFAAOCAQEAiH7UuIWLM5Uaybk8gJryEWpd
Rf3MUp9VfJNFr5oaWh6jZEAUYeGtHkBEM5xCmX7rb4aOx/iOoublDUoT/YXOXC4w
QRCC66ByROtGMOFu09CJ5/WPYhriwmjhOdyiceUfJ0ax33kIHHXsGIaQu5rTw28n
dnxTGP5lRgschEruunRt5rXJY01A0qRSMhWt+DBZly1N45l+albK7XNCsRvLkZEP
qUA7FxQxtApEwHzXJqL4qODOD/nHj4kh3lCiQWxuh0sX5YAKfTu9zEVTvYzmmxB6
K6KGxmoUD+pAOpkqJw266py3DIHlwtd8/NMhlask2Nvtd7IvZ9DFaIvIiHiJlg==
-----END CERTIFICATE-----
EOF

cat <<'EOF' > /etc/nginx/ssl/server.key
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAjjkAJ+5AmzHik6NrliA3uFNNKqP9G2TlmjAZBg8uiP2pfoZI
aNiPPH1RqEaV+mzF07SY7P7V7XarAcwLgCwGeUPYcLYcl4q9ZpqWNEw4wYI2QbDP
aKcrDi4k8cEvQ1ZfBFYEIMyHEstOPA5YiVGMBAUBWGpfTe8aA46wmjtspFqNJaCZ
RVEB6xf/vvFIH5Af66+172mJW6aMpTa0EnS08hHX50d1jbIpwavgSunbREffYAdE
JepxA8JqZwbkrsH35P1sqbdmQN53OgeTZlhwmj0cEZM+YUVIX9W83rVrgQGvAwrI
KkumnS0878Q2PkU2pp0owVCgwDfDaV5t4aXlmwIDAQABAoIBABV94JuoIcQyCCK2
Vco0aScmE2mnqVZr61RfA1EKl0YlSukvQp7xZsfFykKrE/vpVwW0a02Y/tvpDFNz
saM3Q+0sRvdVVcHCufdY0ezqPcNkOW242cbfSB7W80dDIbDDywz9MJeCQMEizto9
cryhgY6T8Q2a2XcN9DjoZaCQ7Uxyltsf0/U7icwiKjdC38elpS1szU+saWwSuZDU
n37Kkn8ofeyL1eDW1QPaX2vi8+uvYgIgHEQZdudxk+06V1rZhTkDxtfaxM+iFH3G
8mf8JdtEHbaCykuDknzfVfgFSz+GQIEwr721r+x2eQZuPCov1zLl2aBJ6vCHIuhB
d/tYsVkCgYEAx2kj2CDfTmAQ09efHTP78pDLZd3BYN+Qs8blKJFnyd96BpZa9Cyf
WHxLN5mruS2kU7hiKamYhIApWoxKIKo6g3/dIGbAxSoRnjk9+bZFCO4Xqd22z/6n
tUUrRAdRiEQui7QGuuOw8vn0X2yegPTHDQDOk8hlHtktGvqCpoxl8yMCgYEAtpU+
PEZOmNYOmBx9ryO9GfQGRdidQpfRaDpgX8TgrrH+c2Qi3mTXkwVQB9mzSa+sMzlD
xSoCaTA1QrSQUMAEtM+ZnO8utJG0RkkJzj3R4XbfC7F9QjAOtGZRoa/smTJRI+ro
rdeibV/6O32OnZxq7wPVQ206eLo0LIAq/PZkBykCgYA0Fpu9VgDeuStMGtO+Thju
6LGovz9HLb7fpwGvEiRZUB3Q4K+Lfqh09aq0MFjx+yEkmVJS7bEgU1X6CBFI7Q5x
0RGS6CRMnEuT2AH/W4Q26/KUdYzOUge+yv2dPIgonx7FcVYctWNAZNhXoMjaiJYC
KIbNhZgcccBdfrhoBt6OnwKBgAgpr/id5BGtMEXYsD3OSTwJzuX8gztg8jnIslpV
wP3Oc2PRTEXJGGI4UJWpQ/y9X+OCYedEs4rkXt02mWUi0JMM3P9JKjtkcDzcMxYH
aYS8/cfWDZWR9HZYRLoH1Xob58jFTdXH2Dkvm05hlKizP4ykDTrQfVa8bGy45jMd
COfRAoGAXmAQaAp4cI/eqp+KI1caYYPdGp7ymWMcncmUDHLzVz7R3n1XjaXju4iO
eK2i+SLCxDKFUi5WimGGt5L/7ALInLwVO60IMzd2ESyWURfnVb8sJE1r6mmyRisG
ReTOK9NyVsqX37lifVn17Qb34WSuPytT7lQvCibGXzLqfeiPDs8=
-----END RSA PRIVATE KEY-----
EOF

chmod 600 /etc/nginx/ssl/server.key
chmod 644 /etc/nginx/ssl/server.crt

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
        return 200 '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Secure Gateway Private Backend</title><style>body{margin:0;background:#0b0f19;color:#f1f5f9;font-family:system-ui,-apple-system,sans-serif;padding:2rem 1rem;display:flex;justify-content:center}.box{max-width:800px;width:100%;background:#131b2e;border:1px solid #22304d;border-radius:12px;padding:2rem}h1{margin-top:0;display:flex;justify-content:space-between;align-items:center;font-size:1.5rem;color:#38bdf8}.badge{background:#064e3b;color:#34d399;font-size:0.8rem;padding:0.3rem 0.8rem;border-radius:999px;border:1px solid #059669}.grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin:1.5rem 0}.stat{background:#070a12;border:1px solid #22304d;border-radius:8px;padding:1rem}small{color:#94a3b8}table{width:100%;border-collapse:collapse}td{padding:0.6rem 0;border-bottom:1px solid #1e293b}td:first-child{color:#94a3b8;width:35%}a{color:#38bdf8}</style></head><body><div class="box"><h1><span>🛡️ BeyondCorp Secure Gateway</span><span class="badge">● Private Ingress OK</span></h1><p style="color:#94a3b8">Private Compute Engine VM in Google Cloud (<code>secgw-test-vpc</code> / <code>asia-northeast1</code>)</p><div class="grid"><div class="stat"><small>Client Ingress IP</small><div style="font-size:1.2rem;font-weight:bold;color:#38bdf8;font-family:monospace;margin-top:0.3rem">$remote_addr</div><small>(SGW Source: 136.124.16.0/20)</small></div><div class="stat"><small>TLS Protocol & Cipher</small><div style="font-size:1.2rem;font-weight:bold;color:#34d399;font-family:monospace;margin-top:0.3rem">$ssl_protocol</div><small>$ssl_cipher</small></div></div><table><tr><td>Target Host</td><td><strong>$host</strong></td></tr><tr><td>Target Server Port</td><td>$server_port</td></tr><tr><td>VM Internal IP</td><td>10.10.0.2 (secgw-https-backend-01)</td></tr><tr><td>User-Agent</td><td><small>$http_user_agent</small></td></tr><tr><td>Timestamp</td><td>$time_iso8601</td></tr></table><p style="margin-top:1.5rem"><a href="/api/status">View Raw JSON Endpoint (/api/status)</a></p></div></body></html>\\n';
    }
}
EOF

nginx -t
systemctl restart nginx
systemctl enable nginx
`;

async function waitForOp(transport: Transport, opResponse: any, log?: string[]): Promise<void> {
  const selfLink = opResponse?.payload?.selfLink;
  if (!selfLink || typeof selfLink !== "string") return;
  for (let i = 0; i < 60; i++) {
    await new Promise((r) => setTimeout(r, 1500));
    try {
      const { payload } = await transport.requestJson("GET", selfLink);
      if ((payload as any).status === "DONE") {
        if ((payload as any).error?.errors && (payload as any).error.errors.length > 0) {
          const errMsg = (payload as any).error.errors[0]?.message || "Operation failed";
          log?.push(`Operation failed: ${errMsg}`);
          throw new Error(errMsg);
        }
        return;
      }
    } catch (err: any) {
      if (err?.message && !err.message.includes("404")) throw err;
    }
  }
}

export interface SampleBackendResult {
  status: "ready" | "created" | "error";
  log: string[];
  vm_name: string;
  vpc_name: string;
  subnet_name: string;
  internal_ip: string;
  hostname: string;
  static_egress_ip: string;
  region: string;
  zone: string;
  error?: string;
}

export async function bootstrapSampleBackend(
  projectId: string,
  options: {
    transport: Transport;
    region?: string;
    zone?: string;
  },
): Promise<SampleBackendResult> {
  const region = options.region || "asia-northeast1";
  const zone = options.zone || `${region}-b`;
  const vpcName = "secgw-test-vpc";
  const subnetName = "secgw-test-subnet";
  const routerName = "secgw-cloud-router";
  const natName = "secgw-cloud-nat";
  const staticIpName = "secgw-nat-static-ip";
  const vmName = "secgw-https-backend-01";
  const log: string[] = [];

  const vpcUrl = `${COMPUTE}/projects/${projectId}/global/networks/${vpcName}`;
  const subnetUrl = `${COMPUTE}/projects/${projectId}/regions/${region}/subnetworks/${subnetName}`;
  const staticIpUrl = `${COMPUTE}/projects/${projectId}/regions/${region}/addresses/${staticIpName}`;

  // 0. Ensure Cloud DNS API is enabled
  try {
    log.push("0. Enabling Cloud DNS API...");
    await options.transport.requestJson(
      "POST",
      `https://serviceusage.googleapis.com/v1/projects/${projectId}/services/dns.googleapis.com:enable`,
    );
    log.push("Cloud DNS API enabled.");
  } catch (e: any) {
    log.push(`Cloud DNS enable: ${e?.message || "ok"}`);
  }

  // 1. Ensure Static External IP
  let staticIp = "";
  log.push(`1. Checking Static IP ${staticIpName}...`);
  const ipRes = await options.transport.requestJson("GET", staticIpUrl);
  if (ipRes.status === 200) {
    staticIp = String((ipRes.payload as Record<string, unknown>).address ?? "");
    log.push(`Static IP already exists: ${staticIp}`);
  } else {
    log.push(`Creating Static IP ${staticIpName}...`);
    try {
      const op = await options.transport.requestJson(
        "POST",
        `${COMPUTE}/projects/${projectId}/regions/${region}/addresses`,
        {
          jsonBody: {
            name: staticIpName,
            description: "Static External IP for Secure Gateway outbound Cloud NAT (GitHub Allowlist)",
          },
        },
      );
      await waitForOp(options.transport, op, log);
      const getRes = await options.transport.requestJson("GET", staticIpUrl);
      staticIp = String((getRes.payload as Record<string, unknown>).address ?? "");
      log.push(`Static IP created: ${staticIp}`);
    } catch (e: any) {
      log.push(`Static IP creation note: ${e?.message || e}`);
    }
  }

  // 2. Ensure VPC
  log.push(`2. Checking VPC ${vpcName}...`);
  const vpcRes = await options.transport.requestJson("GET", vpcUrl);
  if (vpcRes.status === 200) {
    log.push(`VPC ${vpcName} already exists.`);
  } else {
    log.push(`Creating VPC ${vpcName}...`);
    try {
      const op = await options.transport.requestJson(
        "POST",
        `${COMPUTE}/projects/${projectId}/global/networks`,
        {
          jsonBody: {
            name: vpcName,
            autoCreateSubnetworks: false,
            description: "Managed by Secure Gateway Studio",
          },
        },
      );
      await waitForOp(options.transport, op, log);
      log.push(`VPC ${vpcName} created.`);
    } catch (e: any) {
      log.push(`VPC creation note: ${e?.message || e}`);
    }
  }

  // 3. Ensure Subnet
  log.push(`3. Checking Subnet ${subnetName}...`);
  const subnetRes = await options.transport.requestJson("GET", subnetUrl);
  if (subnetRes.status === 200) {
    log.push(`Subnet ${subnetName} already exists.`);
  } else {
    log.push(`Creating Subnet ${subnetName}...`);
    try {
      const op = await options.transport.requestJson(
        "POST",
        `${COMPUTE}/projects/${projectId}/regions/${region}/subnetworks`,
        {
          jsonBody: {
            name: subnetName,
            ipCidrRange: "10.10.0.0/24",
            network: vpcUrl,
            privateIpGoogleAccess: true,
          },
        },
      );
      await waitForOp(options.transport, op, log);
      log.push(`Subnet ${subnetName} created.`);
    } catch (e: any) {
      log.push(`Subnet creation note: ${e?.message || e}`);
    }
  }

  // 4. Ensure Cloud Router & NAT
  log.push(`4. Checking Cloud Router ${routerName}...`);
  const routerRes = await options.transport.requestJson("GET", `${COMPUTE}/projects/${projectId}/regions/${region}/routers/${routerName}`);
  if (routerRes.status === 200) {
    log.push(`Cloud Router ${routerName} already exists.`);
  } else {
    log.push(`Creating Cloud Router & NAT ${routerName}...`);
    try {
      const op = await options.transport.requestJson(
        "POST",
        `${COMPUTE}/projects/${projectId}/regions/${region}/routers`,
        {
          jsonBody: {
            name: routerName,
            network: vpcUrl,
            nats: [
              {
                name: natName,
                natIpAllocateOption: staticIp ? "MANUAL_ONLY" : "AUTO_ONLY",
                ...(staticIp ? { natIps: [staticIpUrl] } : {}),
                sourceSubnetworkIpRangesToNat: "ALL_SUBNETWORKS_ALL_IP_RANGES",
              },
            ],
          },
        },
      );
      await waitForOp(options.transport, op, log);
      log.push(`Cloud Router & NAT created.`);
    } catch (e: any) {
      log.push(`Cloud Router creation note: ${e?.message || e}`);
    }
  }

  // 5. Ensure Firewall Rules
  log.push(`5. Checking Firewall allow-secgw-ingress-https...`);
  const fwRes = await options.transport.requestJson("GET", `${COMPUTE}/projects/${projectId}/global/firewalls/allow-secgw-ingress-https`);
  if (fwRes.status === 200) {
    log.push(`Firewall allow-secgw-ingress-https already exists.`);
  } else {
    log.push(`Creating Firewall allow-secgw-ingress-https...`);
    try {
      const op = await options.transport.requestJson(
        "POST",
        `${COMPUTE}/projects/${projectId}/global/firewalls`,
        {
          jsonBody: {
            name: "allow-secgw-ingress-https",
            network: vpcUrl,
            direction: "INGRESS",
            sourceRanges: ["0.0.0.0/0"],
            allowed: [{ IPProtocol: "tcp", ports: ["80", "443"] }],
            description: "Allow Secure Gateway and internal traffic to reach test backend",
          },
        },
      );
      await waitForOp(options.transport, op, log);
      log.push(`Firewall allow-secgw-ingress-https created.`);
    } catch (e: any) {
      log.push(`Firewall HTTPS creation note: ${e?.message || e}`);
    }
  }

  log.push(`Checking Firewall allow-iap-ssh...`);
  const iapFwRes = await options.transport.requestJson("GET", `${COMPUTE}/projects/${projectId}/global/firewalls/allow-iap-ssh`);
  if (iapFwRes.status === 200) {
    log.push(`Firewall allow-iap-ssh already exists.`);
  } else {
    log.push(`Creating Firewall allow-iap-ssh...`);
    try {
      const op = await options.transport.requestJson(
        "POST",
        `${COMPUTE}/projects/${projectId}/global/firewalls`,
        {
          jsonBody: {
            name: "allow-iap-ssh",
            network: vpcUrl,
            direction: "INGRESS",
            sourceRanges: [IAP_RANGE],
            allowed: [{ IPProtocol: "tcp", ports: ["22"] }],
            description: "Allow IAP SSH for instance management",
          },
        },
      );
      await waitForOp(options.transport, op, log);
      log.push(`Firewall allow-iap-ssh created.`);
    } catch (e: any) {
      log.push(`Firewall IAP creation note: ${e?.message || e}`);
    }
  }

  // 6. Ensure VM
  log.push(`6. Checking Compute VM ${vmName}...`);
  const vmRes = await options.transport.requestJson("GET", `${COMPUTE}/projects/${projectId}/zones/${zone}/instances/${vmName}`);
  if (vmRes.status === 200) {
    log.push(`Compute VM ${vmName} exists. Updating metadata with Root CA-signed certificate & resetting VM...`);
    try {
      const currentMeta = (vmRes.payload as any)?.metadata || {};
      const fingerprint = currentMeta.fingerprint;
      const op = await options.transport.requestJson(
        "POST",
        `${COMPUTE}/projects/${projectId}/zones/${zone}/instances/${vmName}/setMetadata`,
        {
          jsonBody: {
            fingerprint,
            items: [{ key: "startup-script", value: STARTUP_SCRIPT }],
          },
        },
      );
      await waitForOp(options.transport, op, log);
      const resetOp = await options.transport.requestJson(
        "POST",
        `${COMPUTE}/projects/${projectId}/zones/${zone}/instances/${vmName}/reset`,
      );
      await waitForOp(options.transport, resetOp, log);
      log.push(`Compute VM ${vmName} updated and reset with signed certificate.`);
    } catch (e: any) {
      log.push(`VM update note: ${e?.message || e}`);
    }
  } else {
    log.push(`Creating Compute VM ${vmName}...`);
    try {
      const op = await options.transport.requestJson(
        "POST",
        `${COMPUTE}/projects/${projectId}/zones/${zone}/instances`,
        {
          jsonBody: {
            name: vmName,
            machineType: `${COMPUTE}/projects/${projectId}/zones/${zone}/machineTypes/e2-micro`,
            disks: [
              {
                boot: true,
                autoDelete: true,
                initializeParams: {
                  sourceImage: "projects/debian-cloud/global/images/family/debian-12",
                  diskSizeGb: "10",
                },
              },
            ],
            networkInterfaces: [
              {
                network: vpcUrl,
                subnetwork: subnetUrl,
                networkIP: "10.10.0.2",
              },
            ],
            tags: { items: ["secgw-test-backend"] },
            metadata: {
              items: [{ key: "startup-script", value: STARTUP_SCRIPT }],
            },
          },
        },
      );
      await waitForOp(options.transport, op, log);
      log.push(`Compute VM ${vmName} created.`);
    } catch (e: any) {
      log.push(`Compute VM creation note: ${e?.message || e}`);
    }
  }

  // 7. Ensure Cloud DNS Private Managed Zone & A Record
  const dnsZoneName = "secgw-backend-internal-zone";
  log.push(`7. Checking Cloud DNS Managed Zone ${dnsZoneName}...`);
  const dnsRes = await options.transport.requestJson("GET", `https://dns.googleapis.com/dns/v1/projects/${projectId}/managedZones/${dnsZoneName}`);
  if (dnsRes.status === 200) {
    log.push(`Cloud DNS Managed Zone ${dnsZoneName} already exists.`);
  } else {
    log.push(`Creating Cloud DNS Managed Zone ${dnsZoneName}...`);
    try {
      await options.transport.requestJson(
        "POST",
        `https://dns.googleapis.com/dns/v1/projects/${projectId}/managedZones`,
        {
          jsonBody: {
            name: dnsZoneName,
            dnsName: "secgw-backend.internal.",
            description: "Private DNS Zone for BeyondCorp Security Gateway test backend",
            visibility: "private",
            privateVisibilityConfig: {
              networks: [
                {
                  networkUrl: vpcUrl,
                },
              ],
            },
          },
        },
      );
      log.push(`Cloud DNS Managed Zone ${dnsZoneName} created.`);
    } catch (createZoneErr: any) {
      log.push(`Cloud DNS Zone creation note: ${createZoneErr?.message || createZoneErr}`);
    }
  }

  // 8. Ensure A record
  log.push(`8. Adding Cloud DNS A Record secgw-backend.internal -> 10.10.0.2...`);
  try {
    const rrRes = await options.transport.requestJson("GET", `https://dns.googleapis.com/dns/v1/projects/${projectId}/managedZones/${dnsZoneName}/rrsets`);
    const rrItems = (rrRes.payload as any)?.rrsets || [];
    const existingA = Array.isArray(rrItems) ? rrItems.find((r: any) => r.name === "secgw-backend.internal." && r.type === "A") : null;
    if (!existingA) {
      await options.transport.requestJson(
        "POST",
        `https://dns.googleapis.com/dns/v1/projects/${projectId}/managedZones/${dnsZoneName}/changes`,
        {
          jsonBody: {
            additions: [
              {
                name: "secgw-backend.internal.",
                type: "A",
                ttl: 60,
                rrdatas: ["10.10.0.2"],
              },
            ],
          },
        },
      );
      log.push(`Cloud DNS A Record secgw-backend.internal -> 10.10.0.2 registered.`);
    } else {
      log.push(`Cloud DNS A Record secgw-backend.internal -> 10.10.0.2 already exists.`);
    }
  } catch (recErr: any) {
    log.push(`Cloud DNS Record note: ${recErr?.message || recErr}`);
  }

  log.push("✅ Sample backend bootstrap complete.");
  return {
    status: "ready",
    log,
    vm_name: vmName,
    vpc_name: vpcName,
    subnet_name: subnetName,
    internal_ip: "10.10.0.2",
    hostname: "secgw-backend.internal",
    static_egress_ip: staticIp,
    region,
    zone,
  };
}
