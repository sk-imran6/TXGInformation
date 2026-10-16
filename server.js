const express = require("express");
const https = require("https");
const { URL } = require("url");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, "data", "apis.json");
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const MAX_BODY = "30kb";

app.disable("x-powered-by");
app.use(express.json({ limit: MAX_BODY }));
app.use(express.static(path.join(__dirname, "public"), {
  extensions: ["html"],
  setHeaders: res => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  }
}));

function loadApis() {
  try {
    const parsed = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
    return Array.isArray(parsed) ? parsed : [];
  } catch { return []; }
}
function saveApis(apis) {
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  const temp = DATA_FILE + ".tmp";
  fs.writeFileSync(temp, JSON.stringify(apis, null, 2), { mode: 0o600 });
  fs.renameSync(temp, DATA_FILE);
}
let apis = loadApis();
function adminOnly(req, res, next) {
  if (!ADMIN_PASSWORD) return res.status(503).json({ error: "Admin is not configured. Set ADMIN_PASSWORD in Render Environment." });
  const supplied = String(req.headers["x-admin-password"] || "");
  if (supplied.length !== ADMIN_PASSWORD.length ||
      !require("crypto").timingSafeEqual(Buffer.from(supplied), Buffer.from(ADMIN_PASSWORD))) {
    return res.status(401).json({ error: "Admin password incorrect." });
  }
  next();
}
function getJson(url, timeout = 10000) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:") return reject(new Error("HTTPS required"));
    const req = https.get(parsed, {
      headers: { "User-Agent": "TXG-Information/9.0", "Accept": "application/json" }
    }, res => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", chunk => {
        body += chunk;
        if (body.length > 1_000_000) req.destroy(new Error("Response too large"));
      });
      res.on("end", () => {
        try {
          const data = JSON.parse(body);
          if (res.statusCode < 200 || res.statusCode >= 300) return reject(new Error("Provider HTTP " + res.statusCode));
          resolve(data);
        } catch { reject(new Error("Provider returned invalid JSON")); }
      });
    });
    req.setTimeout(timeout, () => req.destroy(new Error("Provider timeout")));
    req.on("error", reject);
  });
}
const validDomain = s => /^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(s);
const validIp = s => /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(s);

app.get("/api/health", (_req, res) => res.json({ ok: true, service: "TXG Information", theme: "Crimson X" }));
app.post("/api/admin/check", adminOnly, (_req, res) => res.json({ ok: true }));

// Public list exposes names and IDs only. URLs remain server-side.
app.get("/api/apis", (_req, res) => {
  res.set("Cache-Control", "no-store");
  res.json({ apis: apis.map(a => ({ id: a.id, name: a.name, favorite: !!a.favorite, kind: a.kind || "custom" })) });
});

app.post("/api/admin/apis", adminOnly, (req, res) => {
  const name = String(req.body.name || "").trim();
  const url = String(req.body.url || "").trim();
  if (!name || name.length > 60) return res.status(400).json({ error: "API name required (max 60 characters)." });
  let parsed;
  try { parsed = new URL(url); } catch { return res.status(400).json({ error: "Enter a valid API URL." }); }
  if (parsed.protocol !== "https:") return res.status(400).json({ error: "Only HTTPS API URLs are allowed." });
  if (!url.includes("{Message}")) return res.status(400).json({ error: "URL must include {Message} where the user's input goes." });
  if (apis.length >= 200) return res.status(400).json({ error: "Maximum 200 APIs reached." });
  const api = { id: require("crypto").randomUUID(), name, url, favorite: false, kind: "custom", createdAt: new Date().toISOString() };
  apis.push(api);
  try { saveApis(apis); } catch { apis.pop(); return res.status(500).json({ error: "Could not save APIs. Configure persistent storage." }); }
  res.status(201).json({ ok: true, api: { id: api.id, name: api.name, favorite: api.favorite, kind: api.kind } });
});

app.delete("/api/admin/apis/:id", adminOnly, (req, res) => {
  const before = apis.length;
  apis = apis.filter(a => a.id !== req.params.id);
  if (apis.length === before) return res.status(404).json({ error: "API not found." });
  try { saveApis(apis); } catch { return res.status(500).json({ error: "Could not save changes." }); }
  res.json({ ok: true });
});

app.post("/api/admin/apis/:id/favorite", adminOnly, (req, res) => {
  const api = apis.find(a => a.id === req.params.id);
  if (!api) return res.status(404).json({ error: "API not found." });
  api.favorite = !!req.body.favorite;
  try { saveApis(apis); } catch { return res.status(500).json({ error: "Could not save changes." }); }
  res.json({ ok: true, favorite: api.favorite });
});

// Runs one custom API. Admin-defined URLs must be HTTPS and the user's input is URL-encoded.
app.get("/api/run/:id", async (req, res) => {
  const api = apis.find(a => a.id === req.params.id);
  if (!api) return res.status(404).json({ error: "API not found." });
  const message = String(req.query.message || "").trim();
  if (!message || message.length > 500) return res.status(400).json({ error: "Enter a message (max 500 characters)." });
  try {
    const target = api.url.replaceAll("{Message}", encodeURIComponent(message));
    const parsed = new URL(target);
    if (parsed.protocol !== "https:") return res.status(400).json({ error: "Only HTTPS URLs are allowed." });
    const result = await getJson(parsed.href, 12000);
    res.set("Cache-Control", "no-store");
    res.json({ ok: true, api: api.name, timestamp: new Date().toISOString(), result });
  } catch {
    res.status(502).json({ error: "API request failed. Check URL template and provider response format." });
  }
});

// Built-in public lookups.
app.get("/api/public", async (req, res) => {
  res.set("Cache-Control", "no-store");
  const tool = String(req.query.tool || "").toLowerCase();
  const q = String(req.query.q || "").trim();
  if (!q || q.length > 253) return res.status(400).json({ error: "Enter a valid query (max 253 characters)." });
  try {
    let data;
    if (tool === "pin") {
      if (!/^\d{6}$/.test(q)) return res.status(400).json({ error: "PIN code must contain 6 digits." });
      data = await getJson("https://api.postalpincode.in/pincode/" + encodeURIComponent(q));
    } else if (tool === "ifsc") {
      if (!/^[A-Za-z]{4}0[A-Za-z0-9]{6}$/.test(q)) return res.status(400).json({ error: "Enter a valid IFSC code." });
      data = await getJson("https://ifsc.razorpay.com/" + encodeURIComponent(q.toUpperCase()));
    } else if (tool === "dns") {
      const domain = q.toLowerCase().replace(/^https?:\/\//, "").split("/")[0];
      if (!validDomain(domain)) return res.status(400).json({ error: "Enter a public domain name." });
      data = { domain, records: {} };
      for (const type of ["A", "AAAA", "MX", "TXT", "NS"]) {
        try { data.records[type] = await getJson("https://dns.google/resolve?name=" + encodeURIComponent(domain) + "&type=" + type); }
        catch { data.records[type] = { error: "Provider unavailable" }; }
      }
    } else if (tool === "ip") {
      if (!validIp(q)) return res.status(400).json({ error: "Enter a valid IPv4 address." });
      const o = q.split(".").map(Number);
      if (o[0] === 10 || o[0] === 127 || o[0] === 0 || (o[0] === 192 && o[1] === 168) ||
          (o[0] === 172 && o[1] >= 16 && o[1] <= 31) || o[0] >= 224) {
        return res.status(400).json({ error: "Private, loopback and reserved IP ranges are not queried." });
      }
      data = await getJson("https://ipwho.is/" + encodeURIComponent(q));
      if (data.success === false) return res.status(502).json({ error: "IP metadata provider could not resolve this address." });
    } else if (tool === "url") {
      let u;
      try { u = new URL(q); } catch { return res.status(400).json({ error: "Enter a full URL including https://" }); }
      if (!["https:", "http:"].includes(u.protocol) || u.username || u.password)
        return res.status(400).json({ error: "Only HTTP/HTTPS URLs without embedded credentials are accepted." });
      data = { url: u.href, hostname: u.hostname, protocol: u.protocol, note: "Basic URL metadata only, not a malware verdict." };
    } else {
      return res.status(400).json({ error: "Tools: ip, dns, url, pin, ifsc." });
    }
    res.json({ ok: true, tool, query: q, timestamp: new Date().toISOString(), data });
  } catch {
    res.status(502).json({ error: "Public data provider unavailable." });
  }
});

app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.listen(PORT, () => console.log("TXG Crimson X running on port " + PORT));
