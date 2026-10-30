/* ========================================================
   Automated Unit Test Suite for Password Strength Analyzer
   Run with: npm test (or node test.js)
   ======================================================== */

const assert = require("assert");
const analyzer = require("./script.js");

console.log("\n🧪 Running Password Strength Analyzer Test Suite...\n");

let passed = 0;
let failed = 0;

function it(description, fn) {
  try {
    fn();
    console.log(`  ✅ PASS: ${description}`);
    passed++;
  } catch (err) {
    console.error(`  ❌ FAIL: ${description}`);
    console.error(`     ${err.message}`);
    failed++;
  }
}

// 1. SHA-1 Tests (Official Cryptographic Vectors)
it("SHA-1 hashes 'password' correctly", async () => {
  const hash = analyzer.pureJsSHA1("password");
  assert.strictEqual(hash, "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
});

it("SHA-1 hashes 'abc' correctly", async () => {
  const hash = analyzer.pureJsSHA1("abc");
  assert.strictEqual(hash, "A9993E364706816ABA3E25717850C26C9CD0D89D");
});

it("SHA-1 hashes empty string correctly", async () => {
  const hash = analyzer.pureJsSHA1("");
  assert.strictEqual(hash, "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709");
});

// 2. Length Check Tests
it("Length check categorizes <8 as fail, 8-11 as warn, >=12 as pass", () => {
  assert.strictEqual(analyzer.checkPasswordLength("12345").status, "fail");
  assert.strictEqual(analyzer.checkPasswordLength("12345678").status, "warn");
  assert.strictEqual(analyzer.checkPasswordLength("12345678901").status, "warn");
  assert.strictEqual(analyzer.checkPasswordLength("123456789012").status, "pass");
});

// 3. Character Types Tests
it("Character counts work for all sets", () => {
  const types = analyzer.checkCharacterTypes("Ab1@");
  assert.strictEqual(types.upper, 1);
  assert.strictEqual(types.lower, 1);
  assert.strictEqual(types.numbers, 1);
  assert.strictEqual(types.special, 1);
});

// 4. Repeated Characters Tests
it("Repeated characters detection identifies sequences like aaa or 111", () => {
  const rep1 = analyzer.checkRepeatedCharacters("passwoord");
  assert.strictEqual(rep1.count, 0); // oo is 2, threshold is 3+

  const rep2 = analyzer.checkRepeatedCharacters("passswoord");
  assert.strictEqual(rep2.count, 1);
  assert.deepStrictEqual(rep2.examples, ["sss"]);

  const rep3 = analyzer.checkRepeatedCharacters("aaa111bbb");
  assert.strictEqual(rep3.count, 3);
});

// 5. Pattern Detection Tests
it("Detects common dictionary passwords including leet speak", () => {
  const p1 = analyzer.detectCommonPatterns("mypassword123");
  assert.ok(p1.some(msg => msg.includes('Contains common word "password"')));

  const p2 = analyzer.detectCommonPatterns("p@ssw0rd");
  assert.ok(p2.some(msg => msg.includes('Contains common word "password"')));
});

it("Detects sequential characters (e.g. abc, 123)", () => {
  const p = analyzer.detectCommonPatterns("xyz999");
  assert.ok(p.some(msg => msg.includes('Predictable sequence "xyz"')));
});

it("Detects keyboard row patterns (e.g. qwe, asd)", () => {
  const p = analyzer.detectCommonPatterns("testqwe12");
  assert.ok(p.some(msg => msg.includes('Keyboard pattern "qwe"')));
});

it("Detects years (1990-2029)", () => {
  const p = analyzer.detectCommonPatterns("Summer2024");
  assert.ok(p.some(msg => msg.includes("Contains a year")));
});

// 6. Strength Calculation Tests
it("Calculates score properly and assigns valid categories", () => {
  const empty = analyzer.calculateStrength("", 0, { upper: 0, lower: 0, numbers: 0, special: 0 }, { count: 0 }, []);
  assert.strictEqual(empty.score, 0);
  assert.strictEqual(empty.level, "—");

  const weak = analyzer.calculateStrength("abc", 3, { upper: 0, lower: 3, numbers: 0, special: 0 }, { count: 0 }, ["Predictable sequence"]);
  assert.ok(weak.score <= 20);
  assert.strictEqual(weak.level, "Very Weak");

  const strong = analyzer.calculateStrength("V$9!mK8#xL2@qP5*", 16, { upper: 4, lower: 4, numbers: 4, special: 4 }, { count: 0 }, []);
  assert.ok(strong.score >= 80);
});

// 7. Suffix Comparison Tests (HIBP k-anonymity)
it("compareHashSuffix matches the 35-char suffix and ignores 0-padding", () => {
  const sampleResponse = [
    "003CD215739D7C1B2218670D26F81408237:2",
    "000AA6520303038D7E69661448698AD98A3:0", // padded entry
    "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3860533" // matching suffix for 'password'
  ].join("\n");

  const count = analyzer.compareHashSuffix(sampleResponse, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
  assert.strictEqual(count, 3860533);

  const paddedCount = analyzer.compareHashSuffix(sampleResponse, "000AA6520303038D7E69661448698AD98A3");
  assert.strictEqual(paddedCount, 0); // ignores 0-count padding
});

console.log(`\n=================================================`);
console.log(`  Tests Completed: ${passed + failed}`);
console.log(`  Passed: ${passed}`);
console.log(`  Failed: ${failed}`);
console.log(`=================================================\n`);

if (failed > 0) {
  process.exit(1);
}
