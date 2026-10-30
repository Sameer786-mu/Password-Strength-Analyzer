module.exports = (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  const host = (req.headers && req.headers.host) || "localhost";
  const config = {
    PUBLIC_SITE_URL: process.env.PUBLIC_SITE_URL || `https://${host}`,
    HIBP_API_URL: process.env.HIBP_API_URL || "https://api.pwnedpasswords.com/range/",
    HIBP_DOCS_URL: process.env.HIBP_DOCS_URL || "https://haveibeenpwned.com/API/v3#PwnedPasswords",
    NODE_ENV: process.env.NODE_ENV || "production"
  };

  res.writeHead(200, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(config, null, 2));
};
