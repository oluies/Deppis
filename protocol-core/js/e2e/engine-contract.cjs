#!/usr/bin/env node
// End-to-end contract test against the ACTUAL linked Scala.js bundle (the `fullLinkJS` artifact a
// consumer loads), as opposed to the in-sbt Scala.js test which exercises the test-linked classes.
// Drives the engine-api.md command sequence the Flutter client uses and asserts the wire contract,
// the no-key-material invariant, and the dev privacy label.
//
// Usage: node engine-contract.cjs <path-to-bundle/main.js>
const assert = require("node:assert");
const path = require("node:path");

const bundle = process.argv[2];
if (!bundle) {
  console.error("usage: node engine-contract.cjs <bundle main.js>");
  process.exit(2);
}

const { ProtocolEngine } = require(path.resolve(bundle));
const engine = new ProtocolEngine();

// apiVersion is exposed and the engine speaks "1".
assert.strictEqual(engine.apiVersion, "1", "apiVersion");

// addBuddy → a 6x5-digit safety number; NEVER any key material on the wire.
const addRaw = engine.handle(
  '{"apiVersion":"1","command":"addBuddy","args":{"sharedSecret":"abc","role":"initiator"}}'
);
assert.ok(!addRaw.includes("pairKey"), "no key material crosses the boundary");
const add = JSON.parse(addRaw);
assert.strictEqual(add.result.safetyNumber.split(" ").length, 6, "safety number shape");
const pairId = add.result.pairId;

// confirmBuddy(match) emits the buddyConfirmed event.
const conf = JSON.parse(
  engine.handle(`{"apiVersion":"1","command":"confirmBuddy","args":{"pairId":"${pairId}","matched":true}}`)
);
assert.strictEqual(conf.events[0].event, "buddyConfirmed", "buddyConfirmed event");

// sendMessage to the now-confirmed buddy is queued.
const send = JSON.parse(
  engine.handle(`{"apiVersion":"1","command":"sendMessage","args":{"pairId":"${pairId}","plaintext":"hi"}}`)
);
assert.strictEqual(send.result.queued, 1, "message queued");

// privacyStatus reports the dev backend (no metadata privacy) + the mandatory label.
const ps = JSON.parse(engine.handle('{"apiVersion":"1","command":"privacyStatus"}'));
assert.strictEqual(ps.result.metadataPrivate, false, "dev build is not metadata-private");
assert.strictEqual(ps.result.label, "DEV, NO METADATA PRIVACY", "mandatory dev label");

// An apiVersion mismatch is refused with the uniform error envelope.
const bad = JSON.parse(engine.handle('{"apiVersion":"9","command":"privacyStatus"}'));
assert.strictEqual(bad.error.code, "api_version", "apiVersion mismatch refused");

// Misshaped input does not throw across the boundary — it returns the uniform error.
const misshaped = JSON.parse(engine.handle("[1,2,3]"));
assert.strictEqual(misshaped.error.code, "bad_request", "misshaped input → bad_request");

console.log("engine-contract e2e: OK (bundle =", path.basename(bundle) + ")");
