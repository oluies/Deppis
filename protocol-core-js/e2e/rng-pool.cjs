// Tests the native engine's secure-RNG pool installer (clients/flutter/assets/rng-pool.js) — the SAME
// file the Dart `engine_factory_io.dart` loads at runtime — so the base64 decoder size math and the
// serve/exhaust behaviour are regression-covered (the native flutter_js path itself can't run under
// `flutter test` on the Dart VM). Run: `node protocol-core-js/e2e/rng-pool.cjs`.
const fs = require('fs');
const vm = require('vm');

const code = fs.readFileSync('clients/flutter/assets/rng-pool.js', 'utf8');
const sb = { Uint8Array, Error };
sb.globalThis = sb;
vm.createContext(sb);
vm.runInContext(code, sb);

function fail(m) { console.error('RNG-POOL-FAIL:', m); process.exit(1); }

// Cover ALL THREE base64 remainder classes so the decoder's partial-group handling can't drift:
//   len % 3 == 0 → no padding, 1 → "==" (2 pad), 2 → "=" (1 pad). For each, the decoded pool must be
// byte-identical to the input and must serve those exact bytes in order, then exhaust distinctly.
for (const len of [63, 64, 65]) {
  const known = Buffer.from(Array.from({ length: len }, (_, i) => (i * 7 + 3) & 0xff));
  const decoded = sb.__installSecureRandomPool(known.toString('base64'));
  if (decoded !== len) fail(`len=${len}: decoder mis-sized the pool: got ${decoded} (size/padding math drifted)`);
  // Serve the whole pool across two draws and check every byte round-tripped.
  const out = new Uint8Array(len);
  sb.globalThis.crypto.getRandomValues(out.subarray(0, len - 5));
  sb.globalThis.crypto.getRandomValues(out.subarray(len - 5));
  if (!out.every((v, i) => v === known[i])) fail(`len=${len}: served bytes != pool (padding/remainder bug)`);
  // Now exhausted — the next byte must throw DISTINCTLY.
  let threw = '';
  try { sb.globalThis.crypto.getRandomValues(new Uint8Array(1)); } catch (e) { threw = e.message; }
  if (!/ENTROPY_POOL_EXHAUSTED/.test(threw)) fail(`len=${len}: exhaustion not surfaced distinctly: "${threw}"`);
}

// getRandomValues returns the same array it was given (Web Crypto contract noble relies on).
sb.__installSecureRandomPool(Buffer.from([1, 2, 3, 4]).toString('base64'));
const arr = new Uint8Array(0);
if (sb.globalThis.crypto.getRandomValues(arr) !== arr) fail('getRandomValues must return its argument');

// --- REFILL path: a synchronous refill makes the pool effectively unbounded ---
// Tiny seed (4 bytes) + a refill that hands back deterministic chunks; draw FAR past the seed and
// assert every byte is served (no ENTROPY_POOL_EXHAUSTED) and the refill was actually invoked.
let refillCalls = 0;
let next = 100; // refilled bytes are a rising counter so we can tell them from the seed
sb.__installSecureRandomPool(Buffer.from([1, 2, 3, 4]).toString('base64'), (n) => {
  refillCalls++;
  const b = Buffer.alloc(n);
  for (let i = 0; i < n; i++) b[i] = next++ & 0xff;
  return b.toString('base64');
});
let total = 0;
for (let i = 0; i < 50; i++) { // 50 draws of 1000 bytes = 50000 >> the 4-byte seed
  const d = new Uint8Array(1000);
  sb.globalThis.crypto.getRandomValues(d); // must NOT throw — refill tops up
  total += d.length;
}
if (total !== 50000) fail(`refill: served ${total}, want 50000`);
if (refillCalls === 0) fail('refill: pool never refilled (sync bridge not exercised)');

// A refill that always returns EMPTY (no progress) must surface exhaustion, not loop forever.
sb.__installSecureRandomPool('', () => '');
let empty = '';
try { sb.globalThis.crypto.getRandomValues(new Uint8Array(8)); } catch (e) { empty = e.message; }
if (!/ENTROPY_POOL_EXHAUSTED/.test(empty)) fail(`empty refill must throw, got "${empty}"`);

// A channel that fails to deliver a STRING (null/undefined — the real no-sync-bridge failure) must
// surface the SAME distinct error, not a TypeError from decoding undefined.
for (const bad of [() => null, () => undefined, () => 42]) {
  sb.__installSecureRandomPool('', bad);
  let why = '';
  try { sb.globalThis.crypto.getRandomValues(new Uint8Array(4)); } catch (e) { why = e.message; }
  if (!/ENTROPY_POOL_EXHAUSTED/.test(why)) fail(`non-string refill must throw ENTROPY_POOL_EXHAUSTED, got "${why}"`);
}

// An OVERSIZED single draw (far larger than one refill chunk) must be satisfied by looping the refill,
// not capped/thrown — proving "effectively unbounded" for a single call.
let big = 0;
const cap = 1000; // host delivers at most 1000 bytes per refill
sb.__installSecureRandomPool('', (n) => { big++; return Buffer.alloc(Math.min(n, cap)).toString('base64'); });
const huge = new Uint8Array(7777); // >> cap → needs ~8 refill loops in ONE getRandomValues call
sb.globalThis.crypto.getRandomValues(huge);
if (huge.length !== 7777) fail('oversized single draw not fully served');
if (big < 7) fail(`oversized draw should loop the refill (~8x), only ${big}`);

console.log('RNG-POOL-OK: decoder correct for all base64 paddings; no-refill exhausts distinctly; ' +
  `sync refill serves unbounded incl. oversized single draws; channel-failure surfaces ENTROPY_POOL_EXHAUSTED`);
