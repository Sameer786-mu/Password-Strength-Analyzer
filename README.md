# SecureCheck – Password Strength Analyzer

SecureCheck is a web-based cybersecurity awareness and password analysis tool. It evaluates password strength in real time, checks for predictable patterns, and integrates the **Have I Been Pwned (HIBP)** Pwned Passwords API with **k-anonymity** to verify whether a password has been compromised in known data leaks.

## Project Structure
```
Password-Strength-Analyzer/
├── index.html        Page layout: navbar, hero, analyzer, breach checker, tips, about, footer
├── style.css         Dark navy glassmorphism design, animations, responsive layout
├── script.js         Core logic: strength analysis, pattern detection, SHA-1, HIBP API
├── config.js         Client-side configuration fallback
├── dev-server.js     Local zero-dependency Node server (serves app & /api/config)
├── package.json      Project scripts (start, dev, test)
├── test.js           Automated unit test suite
├── .env              Local environment variables (configured with public Web APIs)
├── .env.example      Template for environment configuration
└── assets/
    ├── images/
    └── icons/
```

## Quick Start

### Option 1: Run with Node.js (Recommended)
You do not need to install any external dependencies! Standard Node.js is all that is required:

```bash
# Start the local development server (reads .env automatically)
npm start
# or: node dev-server.js
```
Then open: **`http://localhost:3000`** in your browser.

To run automated unit tests:
```bash
npm test
# or: node test.js
```

### Option 2: Run with VS Code Live Server
1. Open the project folder in VS Code.
2. Install the **Live Server** extension.
3. Right-click `index.html` → **Open with Live Server**.

*(A pure JavaScript SHA-1 fallback is also built-in, so the analyzer functions properly even if opened directly in restricted browser environments).*

## Environment Configuration (`.env`)

The `.env` file configures the web application and external API endpoints:

```env
PORT=3000
HOST=localhost
PUBLIC_SITE_URL=http://localhost:3000
HIBP_API_URL=https://api.pwnedpasswords.com/range/
HIBP_DOCS_URL=https://haveibeenpwned.com/API/v3#PwnedPasswords
NODE_ENV=development
```

When running `dev-server.js`, the configuration is served dynamically to the client via `/api/config` and `/config.js`.

## Key Functions

| Function | What it does |
|---|---|
| `analyzePassword()` | Runs every check and updates the UI |
| `checkPasswordLength()` | Evaluates length (fail < 8, warn 8–11, pass ≥ 12) |
| `checkCharacterTypes()` | Counts uppercase, lowercase, numbers, and symbols |
| `detectCommonPatterns()` | Flags dictionary words, leet speak, sequences, keyboard rows, years |
| `calculateStrength()` | Calculates educational 0–100 score and 5 strength levels |
| `generateSuggestions()` | Generates tailored security advice and breach alerts |
| `calculateSHA1()` | Computes local SHA-1 fingerprint with Web Crypto and pure JS fallback |
| `checkPasswordBreach()` | Sends only a 5-char hash prefix to HIBP with padding |
| `compareHashSuffix()` | Matches the remaining 35-char suffix client-side |
| `displayBreachResults()` | Renders Compromised, Not Found, or Error views with retry |
| `clearAnalyzer()` | Resets the input and all dashboard cards |

## Cryptography & Privacy (k-Anonymity)

1. Your password is never sent across the internet.
2. The browser generates a 40-character SHA-1 hex hash locally:
   `password` → `5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8`
3. Only the first 5 characters (`5BAA6`) are sent to `https://api.pwnedpasswords.com/range/5BAA6`.
4. The server returns hundreds of matching hash suffixes sharing that prefix.
5. The browser compares the remaining 35 characters locally.
6. The server never learns what password was entered.

## Test Cases (Demonstration Passwords)

| Input | Expected Output |
|---|---|
| *(empty)* + Check | Prompts to enter a password |
| `abc` | Very Weak, sequence detected |
| `sunshine` | Weak, common word detected |
| `SunShine` | Medium, uppercase + lowercase detected |
| `Sunshine2024` | Year pattern warning |
| `Sunshine2024!` | Special character passed |
| `aaa111bbb` | Repeated characters warning |
| `password` → Exposure Check | **COMPROMISED** (millions of occurrences) |
| `xT9#vq!Lm2@pRz8&Kw` → Check | **NOT FOUND** in known breaches |
| Eye icon | Toggles password visibility |
| X icon | Clears form and resets analyzer |
| Esc key | Closes open modal dialogs |
