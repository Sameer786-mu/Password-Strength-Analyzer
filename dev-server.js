/* ========================================================
   SecureCheck – Local Development & Production Server
   Zero external dependencies: uses built-in Node.js modules.
   Loads .env, serves static assets, and provides /api/config.
   ======================================================== */

const http = require("http");
const fs = require("fs");
const path = require("path");

// Simple .env parser to support any Node version without dependencies
function loadEnv() {
  const envPath = path.join(__dirname, ".env");
  if (!fs.existsSync(envPath)) return {};
  const content = fs.readFileSync(envPath, "utf-8");
  const config = {};
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eqIdx = trimmed.indexOf("=");
    if (eqIdx !== -1) {
      const key = trimmed.slice(0, eqIdx).trim();
      let val = trimmed.slice(eqIdx + 1).trim();
      // Remove enclosing quotes if any
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1);
      }
      config[key] = val;
      // Set to process.env if not already set
      if (!process.env[key]) {
        process.env[key] = val;
      }
    }
  }
  return config;
}

const envConfig = loadEnv();
const PORT = parseInt(process.env.PORT || envConfig.PORT || "3000", 10);
const HOST = process.env.HOST || envConfig.HOST || "localhost";

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".txt": "text/plain; charset=utf-8",
  ".woff": "font/woff",
  ".woff2": "font/woff2"
};

const server = http.createServer((req, res) => {
  // CORS headers for safety and compatibility
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  const url = new URL(req.url, `http://${req.headers.host || HOST}`);
  let pathname = decodeURIComponent(url.pathname);

  // API endpoint for frontend configuration
  if (pathname === "/api/config") {
    const publicConfig = {
      PORT,
      HOST,
      PUBLIC_SITE_URL: process.env.PUBLIC_SITE_URL || envConfig.PUBLIC_SITE_URL || `http://${HOST}:${PORT}`,
      HIBP_API_URL: process.env.HIBP_API_URL || envConfig.HIBP_API_URL || "https://api.pwnedpasswords.com/range/",
      HIBP_DOCS_URL: process.env.HIBP_DOCS_URL || envConfig.HIBP_DOCS_URL || "https://haveibeenpwned.com/API/v3#PwnedPasswords",
      NODE_ENV: process.env.NODE_ENV || envConfig.NODE_ENV || "development"
    };
    res.writeHead(200, { "Content-Type": "application/json; charset=utf-8" });
    res.end(JSON.stringify(publicConfig, null, 2));
    return;
  }

  // Dynamic config.js script endpoint
  if (pathname === "/config.js") {
    const publicConfig = {
      PORT,
      HOST,
      PUBLIC_SITE_URL: process.env.PUBLIC_SITE_URL || envConfig.PUBLIC_SITE_URL || `http://${HOST}:${PORT}`,
      HIBP_API_URL: process.env.HIBP_API_URL || envConfig.HIBP_API_URL || "https://api.pwnedpasswords.com/range/",
      HIBP_DOCS_URL: process.env.HIBP_DOCS_URL || envConfig.HIBP_DOCS_URL || "https://haveibeenpwned.com/API/v3#PwnedPasswords",
      NODE_ENV: process.env.NODE_ENV || envConfig.NODE_ENV || "development"
    };
    const jsContent = `window.APP_CONFIG = Object.assign(window.APP_CONFIG || {}, ${JSON.stringify(publicConfig)});`;
    res.writeHead(200, { "Content-Type": "application/javascript; charset=utf-8" });
    res.end(jsContent);
    return;
  }

  // Normalize path and default to index.html
  if (pathname === "/" || pathname === "") {
    pathname = "/index.html";
  }

  const safePath = path.normalize(path.join(__dirname, pathname));
  // Prevent directory traversal outside the project directory
  if (!safePath.startsWith(__dirname)) {
    res.writeHead(403, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("403 Forbidden");
    return;
  }

  fs.stat(safePath, (err, stats) => {
    if (err || !stats.isFile()) {
      res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("404 Not Found");
      return;
    }

    const ext = path.extname(safePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || "application/octet-stream";

    res.writeHead(200, { "Content-Type": contentType });
    fs.createReadStream(safePath).pipe(res);
  });
});

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`\n=================================================`);
    console.log(`  SecureCheck Local Server Running!`);
    console.log(`  Local URL:        http://localhost:${PORT}`);
    console.log(`  Config Endpoint:  http://localhost:${PORT}/api/config`);
    console.log(`  HIBP Range API:   ${process.env.HIBP_API_URL || envConfig.HIBP_API_URL || "https://api.pwnedpasswords.com/range/"}`);
    console.log(`=================================================\n`);
  });
}

module.exports = server;
