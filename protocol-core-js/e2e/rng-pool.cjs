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

console.log('RNG-POOL-OK: decoder correct for all base64 paddings (0/1/2), serves OS bytes in order, exhaustion throws ENTROPY_POOL_EXHAUSTED');
