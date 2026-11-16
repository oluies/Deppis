// A stand-in for the flutter_js runtime, for Dart VM tests (`flutter test` cannot host JavaScriptCore
// or QuickJS). It loads the REAL native engine bundle and the REAL provider-bridge.js, then:
//   stdin  — one JSON-encoded string of JS code per line, evaluated in order (the host's `run`)
//   stdout — one JSON object per line: {"ready": true} once loaded, then every flutter_js
//            `sendMessage(channel, message)` as {"channel": ..., "message": ...}
// The only difference from the device is the JS engine (V8 here) and the CSPRNG (Node's webcrypto
// instead of the Dart `Random.secure()` pool). Usage: node js_host.cjs <bundle.js> <provider-bridge.js>
const fs = require('fs');
const vm = require('vm');
const readline = require('readline');

const out = (o) => process.stdout.write(JSON.stringify(o) + '\n');

globalThis.sendMessage = (channel, message) => { out({ channel, message }); return null; };
if (!globalThis.crypto) globalThis.crypto = require('crypto').webcrypto;

vm.runInThisContext(fs.readFileSync(process.argv[2], 'utf8'));
vm.runInThisContext(fs.readFileSync(process.argv[3], 'utf8'));
globalThis.__installProviderBridge((s) => globalThis.sendMessage('deppisProvider', s));
out({ ready: typeof globalThis.ProviderSession === 'function' });

readline.createInterface({ input: process.stdin }).on('line', (line) => {
  try {
    vm.runInThisContext(JSON.parse(line));
  } catch (e) {
    out({ error: String(e && e.message) });
  }
});
