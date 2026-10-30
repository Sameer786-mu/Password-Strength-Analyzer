/* ========================================================
   SecureCheck – Client Configuration Fallback
   When running via `npm start` (dev-server.js), configuration
   is loaded dynamically from `.env`.
   When opened statically (e.g. Live Server or file://),
   these defaults are used.
   ======================================================== */
window.APP_CONFIG = window.APP_CONFIG || {
  PORT: 3000,
  PUBLIC_SITE_URL: "http://localhost:3000",
  HIBP_API_URL: "https://api.pwnedpasswords.com/range/",
  HIBP_DOCS_URL: "https://haveibeenpwned.com/API/v3#PwnedPasswords",
  NODE_ENV: "development"
};
