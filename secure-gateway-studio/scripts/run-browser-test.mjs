import { spawn } from "node:child_process";
import { resolve } from "node:path";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";

const port = 9555;
const extensionDist = resolve("extension/dist");
const tempProfile = "C:\\Users\\daiya\\AppData\\Local\\Temp\\sgs-profile-win";

console.log("Launching fresh Chrome on port", port);
console.log("Extension path:", extensionDist);

const chrome = spawn("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", [
  `--remote-debugging-port=${port}`,
  `--user-data-dir=${tempProfile}`,
  `--load-extension=${extensionDist}`,
  `--enable-extensions`,
  `--no-first-run`,
  `--no-default-browser-check`,
  `chrome://extensions`,
], {
  detached: true,
  stdio: "ignore",
});

async function waitReady() {
  for (let i = 0; i < 30; i++) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/json/list`);
      if (res.ok) return await res.json();
    } catch {
      await new Promise(r => setTimeout(r, 500));
    }
  }
  throw new Error("Chrome did not start debugging port");
}

const targets = await waitReady();
console.log("Targets available:", targets.map(t => ({ type: t.type, title: t.title, url: t.url })));

// Connect to browser target to discover extension targets
const versionRes = await fetch(`http://127.0.0.1:${port}/json/version`);
const version = await versionRes.json();
console.log("Browser WebSocket:", version.webSocketDebuggerUrl);

const browserWs = new WebSocket(version.webSocketDebuggerUrl);
await new Promise(r => browserWs.onopen = r);

function sendBrowser(method, params = {}) {
  return new Promise((resolve) => {
    const id = Math.floor(Math.random() * 1000000);
    const handler = (event) => {
      const data = JSON.parse(event.data);
      if (data.id === id) {
        browserWs.removeEventListener("message", handler);
        resolve(data.result);
      }
    };
    browserWs.addEventListener("message", handler);
    browserWs.send(JSON.stringify({ id, method, params }));
  });
}

// Enable target discovery
browserWs.addEventListener("message", (event) => {
  const msg = JSON.parse(event.data);
  if (msg.method === "Target.targetCreated" || msg.method === "Target.targetInfoChanged") {
    console.log("Target event:", msg.method, msg.params.targetInfo.type, msg.params.targetInfo.url);
  }
});

await sendBrowser("Target.setDiscoverTargets", { discover: true });
await new Promise(r => setTimeout(r, 2000));

// Check targets again
const updatedTargets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
console.log("\nAll Targets after discover:");
for (const t of updatedTargets) {
  console.log(` - [${t.type}] "${t.title}" -> ${t.url}`);
}

// Find extension target
let extTarget = updatedTargets.find(t => t.url.startsWith("chrome-extension://") && !t.url.includes("nkeimhogjdpnpccoofpliimaahmaaome") && !t.url.includes("ghbmnnjooekpmoecnnnilnnbdlolhkhi") && !t.url.includes("fignfifoniblkonapihmkfakmlgkbkcf"));

if (!extTarget) {
  // Let's inspect chrome://extensions tab
  const extTab = updatedTargets.find(t => t.url === "chrome://extensions/" || t.url === "chrome://extensions");
  if (extTab) {
    console.log("\nInspecting chrome://extensions page...");
    const tabWs = new WebSocket(extTab.webSocketDebuggerUrl);
    await new Promise(r => tabWs.onopen = r);
    function sendTab(method, params = {}) {
      return new Promise((resolve) => {
        const id = Math.floor(Math.random() * 1000000);
        const handler = (event) => {
          const data = JSON.parse(event.data);
          if (data.id === id) {
            tabWs.removeEventListener("message", handler);
            resolve(data.result);
          }
        };
        tabWs.addEventListener("message", handler);
        tabWs.send(JSON.stringify({ id, method, params }));
      });
    }
    await sendTab("Runtime.enable");
    const extList = await sendTab("Runtime.evaluate", {
      expression: `(function() {
        const mgr = document.querySelector('extensions-manager');
        const items = mgr?.shadowRoot?.querySelector('extensions-item-list')?.shadowRoot?.querySelectorAll('extensions-item');
        if (!items) return 'no items';
        return Array.from(items).map(i => ({
          id: i.id,
          name: i.shadowRoot?.querySelector('#name')?.textContent?.trim(),
          error: i.shadowRoot?.querySelector('.extension-warnings')?.textContent?.trim(),
          inspect: i.shadowRoot?.querySelector('.inspectable-view')?.textContent?.trim(),
        }));
      })()`,
      returnByValue: true,
    });
    console.log("Extension Manager items:", JSON.stringify(extList.result.value, null, 2));
  }
}

// Keep script alive for 2 seconds then exit
await new Promise(r => setTimeout(r, 2000));
process.exit(0);
