/* =========================================================
   SecureCheck – Password Strength Analyzer
   Vanilla JavaScript. No passwords are ever stored or logged.
   ========================================================= */

// A small list of very common passwords / words (educational sample).
const COMMON_PASSWORDS = [
  "password", "123456", "12345678", "qwerty", "abc123", "111111", "letmein",
  "welcome", "admin", "iloveyou", "monkey", "dragon", "football", "baseball",
  "sunshine", "princess", "master", "login", "passw0rd", "starwars", "shadow",
  "superman", "trustno1", "hello", "freedom", "whatever", "qazwsx", "secret",
  "summer", "winter", "spring", "autumn", "michael", "charlie", "pokemon"
];
const KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"];

// Stores ONLY the breach count (never the password) so recommendations can react to it.
let lastBreachCount = null;

// Safe icon renderer to prevent crashes if Lucide CDN is unavailable or offline
function safeCreateIcons() {
  if (typeof lucide !== "undefined" && typeof lucide.createIcons === "function") {
    try {
      lucide.createIcons();
    } catch (err) {
      console.warn("Lucide icons could not be rendered:", err);
    }
  }
}

/* ---------------------------------------------------------
   1. Individual checks
   --------------------------------------------------------- */

// Returns length info and a status (pass / warn / fail)
function checkPasswordLength(password) {
  const length = (password || "").length;
  let status = "fail";
  if (length >= 12) status = "pass";
  else if (length >= 8) status = "warn";
  return { length, status };
}

// Counts each character type
function checkCharacterTypes(password) {
  const pwd = password || "";
  return {
    upper: (pwd.match(/[A-Z]/g) || []).length,
    lower: (pwd.match(/[a-z]/g) || []).length,
    numbers: (pwd.match(/[0-9]/g) || []).length,
    special: (pwd.match(/[^A-Za-z0-9]/g) || []).length,
  };
}

// Finds repeated characters like "aaa" or "1111"
function checkRepeatedCharacters(password) {
  const matches = (password || "").match(/(.)\1{2,}/g) || [];
  return { count: matches.length, examples: matches };
}

// Detects common passwords, sequences, keyboard patterns and years
function detectCommonPatterns(password) {
  if (!password) return [];
  const lower = password.toLowerCase();
  const found = [];

  // Common words (also checks simple "leet" substitutions)
  const deLeet = lower
    .replace(/0/g, "o")
    .replace(/1/g, "i")
    .replace(/3/g, "e")
    .replace(/4/g, "a")
    .replace(/@/g, "a")
    .replace(/\$/g, "s")
    .replace(/5/g, "s");

  for (const word of COMMON_PASSWORDS) {
    if (lower.includes(word) || deLeet.includes(word)) {
      found.push(`Contains common word "${word}"`);
      break;
    }
  }

  // Alphabetical / numeric sequences such as "abc", "123", "cba", "321"
  for (let i = 0; i < lower.length - 2; i++) {
    const a = lower.charCodeAt(i),
      b = lower.charCodeAt(i + 1),
      c = lower.charCodeAt(i + 2);
    if ((b - a === 1 && c - b === 1) || (a - b === 1 && b - c === 1)) {
      found.push(`Predictable sequence "${password.substring(i, i + 3)}"`);
      break;
    }
  }

  // Keyboard patterns like "qwe", "asd"
  for (const row of KEYBOARD_ROWS) {
    for (let i = 0; i < row.length - 2; i++) {
      const chunk = row.substring(i, i + 3);
      if (lower.includes(chunk) && !/^\d+$/.test(chunk)) {
        found.push(`Keyboard pattern "${chunk}"`);
        i = row.length;
      }
    }
  }

  // Years such as 1990 – 2029
  if (/(19|20)\d{2}/.test(password)) found.push("Contains a year (easy to guess)");

  // Only digits
  if (/^\d+$/.test(password)) found.push("Only numbers");

  return [...new Set(found)];
}

/* ---------------------------------------------------------
   2. Score calculation (educational, 0 – 100)
   --------------------------------------------------------- */
function calculateStrength(password, length, types, repeats, patterns) {
  if (!password) return { score: 0, level: "—", color: "var(--muted)" };

  let score = 0;
  // Length: up to 40 points
  score += Math.min(length, 16) * 2.5;
  // Variety: 10 points per type used
  const variety = [types.upper, types.lower, types.numbers, types.special].filter((n) => n > 0).length;
  score += variety * 10;
  // Bonus for very long passwords
  if (length >= 20) score += 10;
  // Penalties
  score -= (repeats.count || 0) * 10;
  score -= (patterns.length || 0) * 12;
  if (length < 6) score = Math.min(score, 15);

  score = Math.max(0, Math.min(100, Math.round(score)));

  const levels = [
    { max: 20, level: "Very Weak", color: "var(--red)" },
    { max: 40, level: "Weak", color: "var(--orange)" },
    { max: 60, level: "Medium", color: "var(--yellow)" },
    { max: 80, level: "Strong", color: "#4ade80" },
    { max: 100, level: "Very Strong", color: "linear-gradient(90deg, var(--green), var(--cyan))" },
  ];
  const match = levels.find((l) => score <= l.max) || levels[levels.length - 1];
  return { score, level: match.level, color: match.color };
}

/* ---------------------------------------------------------
   3. Recommendations
   --------------------------------------------------------- */
function generateSuggestions(password, lengthInfo, types, repeats, patterns) {
  const tips = [];
  if (lastBreachCount && lastBreachCount > 0) {
    tips.push({ text: "This password appears in known data breaches. Replace it immediately everywhere you use it.", critical: true });
  }
  if (!password) return tips;
  if (lengthInfo.length < 12) tips.push({ text: `Increase password length to at least 12–16 characters (currently ${lengthInfo.length}).` });
  if (!types.upper) tips.push({ text: "Add uppercase letters (A–Z)." });
  if (!types.lower) tips.push({ text: "Add lowercase letters (a–z)." });
  if (!types.numbers) tips.push({ text: "Include some numbers (0–9)." });
  if (!types.special) tips.push({ text: "Include special characters such as ! @ # % &." });
  if (repeats && repeats.count) tips.push({ text: 'Avoid repeated characters like "aaa" or "111".' });
  if (patterns && patterns.length) tips.push({ text: "Avoid predictable patterns, common words, sequences and years." });
  tips.push({ text: "Use a unique password for every account." });
  tips.push({ text: "Consider using a password manager to generate and store passwords." });
  tips.push({ text: "Enable multi-factor authentication (MFA) wherever possible." });
  return tips;
}

// Prevents any injected HTML from rendering
function escapeHTML(str) {
  return String(str).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

/* ---------------------------------------------------------
   4. SHA-1 Hashing & Fallback
   --------------------------------------------------------- */

// Pure JS SHA-1 fallback (used if crypto.subtle is restricted, e.g. file:// protocol)
function pureJsSHA1(text) {
  function rotl(n, s) { return (n << s) | (n >>> (32 - s)); }
  const utf8 = unescape(encodeURIComponent(text));
  const words = [];
  for (let i = 0; i < utf8.length; i++) {
    words[i >> 2] = (words[i >> 2] || 0) | (utf8.charCodeAt(i) << (24 - (i % 4) * 8));
  }
  const bitLen = utf8.length * 8;
  words[bitLen >> 5] = (words[bitLen >> 5] || 0) | (0x80 << (24 - (bitLen % 32)));
  words[(((bitLen + 64) >> 9) << 4) + 15] = bitLen;

  let [h0, h1, h2, h3, h4] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
  const w = new Array(80);

  for (let i = 0; i < words.length; i += 16) {
    for (let t = 0; t < 16; t++) w[t] = words[i + t] || 0;
    for (let t = 16; t < 80; t++) w[t] = rotl(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);

    let [a, b, c, d, e] = [h0, h1, h2, h3, h4];
    for (let t = 0; t < 80; t++) {
      let f, k;
      if (t < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999; }
      else if (t < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
      else if (t < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
      else { f = b ^ c ^ d; k = 0xCA62C1D6; }

      const temp = (rotl(a, 5) + f + e + k + w[t]) | 0;
      e = d; d = c; c = rotl(b, 30); b = a; a = temp;
    }
    h0 = (h0 + a) | 0;
    h1 = (h1 + b) | 0;
    h2 = (h2 + c) | 0;
    h3 = (h3 + d) | 0;
    h4 = (h4 + e) | 0;
  }

  return [h0, h1, h2, h3, h4]
    .map((val) => (val >>> 0).toString(16).padStart(8, "0"))
    .join("")
    .toUpperCase();
}

// Local SHA-1 hashing with Web Crypto API and pure JS fallback
async function calculateSHA1(text) {
  if (typeof crypto !== "undefined" && crypto.subtle && typeof crypto.subtle.digest === "function") {
    try {
      const data = new TextEncoder().encode(text);
      const hashBuffer = await crypto.subtle.digest("SHA-1", data);
      return Array.from(new Uint8Array(hashBuffer))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("")
        .toUpperCase();
    } catch {
      return pureJsSHA1(text);
    }
  }
  return pureJsSHA1(text);
}

// Look for our 35-character suffix in the API response (ignores padded "0" entries)
function compareHashSuffix(responseText, suffix) {
  const lines = responseText.split("\n");
  for (const line of lines) {
    const [hashSuffix, count] = line.trim().split(":");
    const n = parseInt(count, 10);
    if (hashSuffix === suffix && n > 0) return n;
  }
  return 0;
}

/* ---------------------------------------------------------
   5. Browser UI & Event Listeners
   --------------------------------------------------------- */
if (typeof document !== "undefined") {
  // DOM references
  const passwordInput = document.getElementById("passwordInput");
  const toggleBtn = document.getElementById("toggleBtn");
  const clearBtn = document.getElementById("clearBtn");
  const analyzeBtn = document.getElementById("analyzeBtn");
  const breachBtn = document.getElementById("breachBtn");
  const meterFill = document.getElementById("meterFill");
  const strengthLabel = document.getElementById("strengthLabel");
  const scoreValue = document.getElementById("scoreValue");
  const analysisCards = document.getElementById("analysisCards");
  const recommendationsEl = document.getElementById("recommendations");
  const breachResult = document.getElementById("breachResult");
  const hashPreview = document.getElementById("hashPreview");

  // Builds one dashboard card
  function card(title, value, desc, status) {
    const icon = status === "pass" ? "check-circle-2" : status === "warn" ? "alert-triangle" : "x-octagon";
    return `<div class="glass a-card ${status}">
      <div class="ic"><i data-lucide="${icon}"></i></div>
      <div><h4>${title}</h4><div class="val">${value}</div><p>${desc}</p></div>
    </div>`;
  }

  function displayResults({ password, lengthInfo, types, repeats, patterns, strength, suggestions }) {
    // Strength meter
    meterFill.style.width = strength.score + "%";
    meterFill.style.background = strength.color;
    strengthLabel.textContent = strength.level;
    strengthLabel.style.color = strength.color.startsWith("linear") ? "var(--green)" : strength.color;
    scoreValue.textContent = strength.score;

    if (!password) {
      meterFill.style.width = "0%";
      meterFill.style.background = "rgba(255, 255, 255, 0.07)";
      strengthLabel.textContent = "—";
      strengthLabel.style.color = "var(--muted)";
      scoreValue.textContent = "0";
      analysisCards.innerHTML = "";
      recommendationsEl.innerHTML = `<li class="muted">Enter a password to receive personalized recommendations.</li>`;
      safeCreateIcons();
      return;
    }

    const has = (n) => (n > 0 ? "pass" : "fail");
    analysisCards.innerHTML = [
      card("Password Length", `${lengthInfo.length} chars`, lengthInfo.status === "pass" ? "Good length" : "12+ recommended", lengthInfo.status),
      card("Uppercase", types.upper, types.upper ? "Uppercase present" : "No uppercase letters", has(types.upper)),
      card("Lowercase", types.lower, types.lower ? "Lowercase present" : "No lowercase letters", has(types.lower)),
      card("Numbers", types.numbers, types.numbers ? "Numbers present" : "No numbers", types.numbers ? "pass" : "warn"),
      card("Special Characters", types.special, types.special ? "Symbols present" : "No symbols", types.special ? "pass" : "warn"),
      card("Repeated Characters", repeats.count, repeats.count ? `Found: ${escapeHTML(repeats.examples.join(", "))}` : "No long repeats", repeats.count ? "warn" : "pass"),
      card("Common Patterns", patterns.length, patterns.length ? escapeHTML(patterns.join(" · ")) : "No common patterns detected", patterns.length ? "fail" : "pass"),
    ].join("");

    recommendationsEl.innerHTML = suggestions
      .map((s) => `<li class="${s.critical ? "critical" : ""}"><i data-lucide="${s.critical ? "siren" : "lightbulb"}"></i><span>${s.text}</span></li>`)
      .join("");

    safeCreateIcons();
  }

  function analyzePassword() {
    const password = passwordInput.value;
    const lengthInfo = checkPasswordLength(password);
    const types = checkCharacterTypes(password);
    const repeats = checkRepeatedCharacters(password);
    const patterns = detectCommonPatterns(password);
    const strength = calculateStrength(password, lengthInfo.length, types, repeats, patterns);
    const suggestions = generateSuggestions(password, lengthInfo, types, repeats, patterns);
    displayResults({ password, lengthInfo, types, repeats, patterns, strength, suggestions });
  }

  async function checkPasswordBreach() {
    const password = passwordInput.value;
    if (!password) {
      displayBreachResults({ type: "empty" });
      return;
    }

    displayBreachResults({ type: "loading" });
    breachBtn.disabled = true;

    try {
      const hash = await calculateSHA1(password);
      const prefix = hash.slice(0, 5); // only this is sent
      const suffix = hash.slice(5); // stays in the browser
      hashPreview.innerHTML = `Hash prefix sent: <code>${prefix}</code>`;

      // Read configured API URL or use official HIBP range endpoint
      const rawApiUrl = (window.APP_CONFIG && window.APP_CONFIG.HIBP_API_URL) || "https://api.pwnedpasswords.com/range/";
      const baseUrl = rawApiUrl.endsWith("/") ? rawApiUrl : `${rawApiUrl}/`;

      const response = await fetch(`${baseUrl}${prefix}`, {
        headers: { "Add-Padding": "true" },
      });
      if (!response.ok) throw new Error("HTTP " + response.status);

      const text = await response.text();
      const count = compareHashSuffix(text, suffix);
      lastBreachCount = count;
      displayBreachResults({ type: count > 0 ? "found" : "notfound", count });
      analyzePassword(); // refresh recommendations with breach status
    } catch (err) {
      // Note: we log only the error, never the password.
      console.warn("Breach check failed:", err.message);
      displayBreachResults({ type: "error" });
    } finally {
      breachBtn.disabled = false;
    }
  }

  function displayBreachResults({ type, count = 0 }) {
    const views = {
      empty: `<div class="state idle"><i data-lucide="keyboard"></i><h3>Please enter a password</h3><p>Type a demonstration password above first.</p></div>`,
      loading: `<div class="state"><div class="loader"></div><h3>Checking breach database…</h3><p>Hashing locally and querying Have I Been Pwned.</p></div>`,
      found: `<div class="state bad"><div class="status-dot"><i data-lucide="shield-alert"></i></div>
        <h3>COMPROMISED PASSWORD</h3>
        <div class="count">${count.toLocaleString()}</div>
        <p><b>Warning!</b> This password has appeared in known data breaches ${count.toLocaleString()} times. Avoid using it. Attackers use these lists first — choose a new, unique password.</p></div>`,
      notfound: `<div class="state good"><div class="status-dot"><i data-lucide="shield-check"></i></div>
        <h3>NOT FOUND IN KNOWN BREACH DATA</h3>
        <p>No matching entry was found in the queried Have I Been Pwned database. Keep using unique passwords, a password manager and multi-factor authentication.</p></div>`,
      error: `<div class="state err"><div class="status-dot"><i data-lucide="wifi-off"></i></div>
        <h3>Unable to complete breach check</h3>
        <p>The network or the Have I Been Pwned service may be unavailable. Please check your connection and try again.</p>
        <button class="btn btn-primary" id="retryBtn"><i data-lucide="refresh-cw"></i> Retry</button></div>`,
    };
    breachResult.innerHTML = views[type];
    safeCreateIcons();
    const retry = document.getElementById("retryBtn");
    if (retry) retry.addEventListener("click", checkPasswordBreach);
  }

  function clearAnalyzer() {
    passwordInput.value = "";
    passwordInput.type = "password";
    toggleBtn.innerHTML = `<i data-lucide="eye"></i>`;
    lastBreachCount = null;
    hashPreview.innerHTML = `Hash prefix sent: <code>—</code>`;
    breachResult.innerHTML = `<div class="state idle"><i data-lucide="radar"></i><h3>No check performed yet</h3><p>Enter a password above and click <b>Check Password Exposure</b>.</p></div>`;
    analyzePassword();
    safeCreateIcons();
    passwordInput.focus();
  }

  // Event listeners
  passwordInput.addEventListener("input", () => {
    // A new password invalidates the previous breach result
    lastBreachCount = null;
    analyzePassword(); // local only – the API is NEVER called on keystrokes
  });

  passwordInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") analyzePassword();
  });

  analyzeBtn.addEventListener("click", analyzePassword);

  breachBtn.addEventListener("click", () => {
    checkPasswordBreach();
    const breachSection = document.getElementById("breach");
    if (breachSection) breachSection.scrollIntoView({ behavior: "smooth" });
  });

  clearBtn.addEventListener("click", clearAnalyzer);

  toggleBtn.addEventListener("click", () => {
    const show = passwordInput.type === "password";
    passwordInput.type = show ? "text" : "password";
    toggleBtn.innerHTML = `<i data-lucide="${show ? "eye-off" : "eye"}"></i>`;
    safeCreateIcons();
  });

  // Mobile menu
  const navLinks = document.getElementById("navLinks");
  const hamburger = document.getElementById("hamburger");
  if (hamburger && navLinks) {
    hamburger.addEventListener("click", () => navLinks.classList.toggle("open"));
    navLinks.querySelectorAll("a").forEach((a) => a.addEventListener("click", () => navLinks.classList.remove("open")));
  }

  // Privacy modal
  const modal = document.getElementById("privacyModal");
  const privacyLink = document.getElementById("privacyLink");
  const closeModal = document.getElementById("closeModal");

  if (privacyLink && modal) {
    privacyLink.addEventListener("click", (e) => {
      e.preventDefault();
      modal.classList.add("open");
    });
  }
  if (closeModal && modal) {
    closeModal.addEventListener("click", () => modal.classList.remove("open"));
  }
  if (modal) {
    modal.addEventListener("click", (e) => {
      if (e.target === modal) modal.classList.remove("open");
    });
    // Accessible Escape key handler
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && modal.classList.contains("open")) {
        modal.classList.remove("open");
      }
    });
  }

  // Scroll reveal animation
  if ("IntersectionObserver" in window) {
    const observer = new IntersectionObserver((entries) => {
      entries.forEach((en) => {
        if (en.isIntersecting) en.target.classList.add("visible");
      });
    }, { threshold: 0.12 });
    document.querySelectorAll(".reveal").forEach((el) => observer.observe(el));
  } else {
    // Fallback if IntersectionObserver is not supported
    document.querySelectorAll(".reveal").forEach((el) => el.classList.add("visible"));
  }

  const yearEl = document.getElementById("year");
  if (yearEl) yearEl.textContent = new Date().getFullYear();

  // Initial call to set clean baseline state
  analyzePassword();
  safeCreateIcons();
}

// Export for automated unit testing in Node.js
if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    COMMON_PASSWORDS,
    KEYBOARD_ROWS,
    checkPasswordLength,
    checkCharacterTypes,
    checkRepeatedCharacters,
    detectCommonPatterns,
    calculateStrength,
    generateSuggestions,
    pureJsSHA1,
    calculateSHA1,
    compareHashSuffix,
  };
}
