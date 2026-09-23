// Headless Chrome screenshot over the DevTools protocol, zero npm deps
// (Node >= 22 ships fetch and WebSocket).
//
//   node scripts/cdp_screenshot.mjs URL OUT.png [WIDTHxHEIGHT] [JS-to-run] [wait-ms]
//
// Used by scripts/readme_screenshots.py for pages that need an interaction
// (e.g. opening a session in the web console) before the capture.
import { spawn } from "node:child_process";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const [url, out, size = "1440x900", script = "", waitArg = "2500"] = process.argv.slice(2);
if (!url || !out) {
  console.error("usage: cdp_screenshot.mjs URL OUT.png [WxH] [JS] [wait-ms]");
  process.exit(2);
}
const [width, height] = size.split("x").map(Number);
const chrome = process.env.CHROME || "google-chrome";
const port = 9300 + Math.floor(Math.random() * 500);
const profile = mkdtempSync(join(tmpdir(), "gp-cdp-"));
const proc = spawn(chrome, [
  "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-first-run",
  `--remote-debugging-port=${port}`, `--user-data-dir=${profile}`,
  `--window-size=${width},${height}`, "about:blank",
], { stdio: "ignore" });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function target() {
  for (let i = 0; i < 50; i++) {
    try {
      const list = await (await fetch(`http://127.0.0.1:${port}/json`)).json();
      const page = list.find((t) => t.type === "page");
      if (page) return page.webSocketDebuggerUrl;
    } catch { /* not up yet */ }
    await sleep(200);
  }
  throw new Error("chrome devtools endpoint never came up");
}

try {
  const ws = new WebSocket(await target());
  await new Promise((r, j) => { ws.onopen = r; ws.onerror = j; });
  let next = 0;
  const pending = new Map();
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
  };
  const send = (method, params = {}) => new Promise((resolve) => {
    const id = ++next;
    pending.set(id, resolve);
    ws.send(JSON.stringify({ id, method, params }));
  });
  await send("Emulation.setDeviceMetricsOverride",
    { width, height, deviceScaleFactor: 1, mobile: false });
  await send("Page.enable");
  await send("Page.navigate", { url });
  await sleep(1500);
  if (script) {
    const res = await send("Runtime.evaluate", { expression: script, awaitPromise: true });
    if (res.result?.exceptionDetails) throw new Error(JSON.stringify(res.result.exceptionDetails));
  }
  await sleep(Number(waitArg));
  const shot = await send("Page.captureScreenshot", { format: "png" });
  writeFileSync(out, Buffer.from(shot.result.data, "base64"));
  console.log(`wrote ${out}`);
  ws.close();
} finally {
  proc.kill();
}
