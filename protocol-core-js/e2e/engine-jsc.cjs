// Standalone JavaScriptCore-compatibility proof for the native engine bundle (Gate 4).
//
// Loads `engine.bundle.js` into a BARE JS context — no Node `require`, no module system, no browser
// globals — exactly what Apple JavaScriptCore (via flutter_js on iOS) provides, PLUS the one thing the
// host must inject: `globalThis.crypto.getRandomValues` backed by a real CSPRNG (here Node webcrypto;
// on iOS, Dart's `Random.secure()`). It then drives the engine through the engine-api JSON boundary
// and asserts a privacy-status read and a real crypto path (addBuddy → X25519 keygen + KDF).
//
// If this passes, the bundle is self-contained and runs outside a browser — the core risk for the
// native iOS engine. Run: `node protocol-core-js/e2e/engine-jsc.cjs <bundle.js>`.
const fs = require('fs');
const vm = require('vm');

const bundlePath = process.argv[2] || 'protocol-core-js/dist/engine.bundle.js';
const code = fs.readFileSync(bundlePath, 'utf8');

// A deliberately minimal global: only what a bare JS engine has + the injected CSPRNG + text codecs.
const sandbox = {
  console,
  crypto: require('crypto').webcrypto, // host-injected CSPRNG (iOS: Dart Random.secure())
  TextEncoder,
  TextDecoder,
};
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
vm.runInContext(code, sandbox);

function fail(m) { console.error('JSC-ENGINE-FAIL:', m); process.exit(1); }

// First, prove the RNG polyfill is REQUIRED (the documented crux): in a context with NO crypto,
// `new ProtocolEngine()` must throw at construction (it mints a per-session cover key). This is what
// the iOS factory's injected `crypto.getRandomValues` fixes — if this ever stops throwing, the engine
// changed its entropy source and the polyfill assumption needs re-checking.
{
  const bare = { console, TextEncoder, TextDecoder };
  bare.globalThis = bare; vm.createContext(bare);
  try { vm.runInContext(code, bare); }
  catch (e) { fail('bundle failed to LOAD in a bare (no-crypto) context: ' + e.message); }
  // The bundle must still DEFINE the constructor without crypto — module evaluation needs no entropy,
  // only construction does. Assert that first, so a missing/renamed export cannot masquerade as the
  // expected crypto-required throw (a bare `new undefined()` would also throw "not a constructor").
  if (typeof bare.ProtocolEngine !== 'function') {
    fail('bundle loaded but did not define globalThis.ProtocolEngine in a bare context');
  }
  let threw = false, why = '';
  try { new bare.ProtocolEngine(); } catch (e) { threw = true; why = e.message || String(e); }
  if (!threw) fail('engine constructed WITHOUT a crypto global — the getRandomValues polyfill is no longer required; re-check the iOS RNG bridge');
  if (/not a constructor/i.test(why)) fail('construction threw "not a constructor" — the bundle did not expose ProtocolEngine, not the expected crypto-required failure');
  console.log('no-crypto: construction throws as expected (RNG polyfill required) —', why.slice(0, 70));
}

const PE = sandbox.ProtocolEngine;
if (typeof PE !== 'function') fail('globalThis.ProtocolEngine is not a constructor');
const engine = new PE();

const priv = JSON.parse(engine.handle(JSON.stringify({ apiVersion: '1', command: 'privacyStatus', args: {} })));
if (!priv.result || typeof priv.result.metadataPrivate !== 'boolean' || !priv.result.label) {
  fail('privacyStatus did not return a privacy result: ' + JSON.stringify(priv));
}

const ab = JSON.parse(engine.handle(JSON.stringify({
  apiVersion: '1', command: 'addBuddy', args: { sharedSecret: 'jsc-e2e-secret', role: 'initiator' },
})));
if (!ab.result || !ab.result.pairId || !ab.result.safetyNumber) {
  fail('addBuddy did not return pairId + safetyNumber: ' + JSON.stringify(ab));
}

console.log('privacyStatus:', priv.result.label, '| addBuddy.pairId:', ab.result.pairId);
console.log('JSC-ENGINE-OK: the bundle runs standalone (no browser) and the crypto path works');
