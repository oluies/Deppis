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

// A known pool: bytes 0..63. Its base64 round-trips to exactly those bytes.
const known = Buffer.from(Array.from({ length: 64 }, (_, i) => i));
const b64 = known.toString('base64');

const len = sb.__installSecureRandomPool(b64);
if (len !== 64) fail(`decoder mis-sized the pool: got ${len}, want 64 (the (len*6)>>3 math drifted)`);

// Serve in order, across multiple draws.
const a = new Uint8Array(40);
sb.globalThis.crypto.getRandomValues(a);
if (!a.every((v, i) => v === i)) fail(`first draw wrong bytes: ${a}`);
const b = new Uint8Array(24);
sb.globalThis.crypto.getRandomValues(b);
if (!b.every((v, i) => v === i + 40)) fail(`second draw wrong bytes: ${b}`);

// Exhaustion: the pool is now empty (64 served) — the next byte must throw DISTINCTLY.
let threw = '';
try { sb.globalThis.crypto.getRandomValues(new Uint8Array(1)); } catch (e) { threw = e.message; }
if (!/ENTROPY_POOL_EXHAUSTED/.test(threw)) fail(`exhaustion not surfaced distinctly: "${threw}"`);

// getRandomValues returns the same array it was given (Web Crypto contract noble relies on).
const arr = new Uint8Array(0);
if (sb.globalThis.crypto.getRandomValues(arr) !== arr) fail('getRandomValues must return its argument');

console.log('RNG-POOL-OK: decoder sizes correctly, serves OS bytes in order, exhaustion throws ENTROPY_POOL_EXHAUSTED');
