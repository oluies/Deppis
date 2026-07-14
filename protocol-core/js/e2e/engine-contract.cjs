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
assert.ok(!addRaw.includes("pairKey"), "no pairKey field on the wire");
const add = JSON.parse(addRaw);
// Strong no-key-material invariant: the result is EXACTLY {pairId, safetyNumber} — not just absent
// of a "pairKey" field, so key bytes cannot hide under any other field name.
assert.deepStrictEqual(
  Object.keys(add.result).sort(),
  ["pairId", "safetyNumber"],
  "result exposes exactly pairId + safetyNumber (no key material under any field)"
);
assert.strictEqual(add.result.safetyNumber.split(" ").length, 6, "safety number shape");
// And no field carries a long high-entropy hex/base64 blob (a serialized 32-byte key would).
for (const [k, v] of Object.entries(add.result)) {
  if (typeof v === "string") {
    assert.ok(!/[A-Za-z0-9+/=]{40,}/.test(v), `field ${k} must not carry a key-sized blob`);
  }
}
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

// Post-quantum pairing prekey (US7): the initiator generates a hybrid-KEM keypair and DEFERS, the
// responder encapsulates, the initiator decapsulates at confirm — proving the actual linked bundle
// carries the KEM (X25519 + ML-KEM-768) and the wire fields round-trip. HONEST SCOPE: this hardens
// only the pairing seed; the ongoing DH ratchet stays classical.
const pqInit = new ProtocolEngine();
const pqResp = new ProtocolEngine();
const pqAdd = JSON.parse(
  pqInit.handle('{"apiVersion":"1","command":"addBuddy","args":{"sharedSecret":"oob","role":"initiator","pqPrekey":true}}')
);
const kemPub = pqAdd.result.kemPublicKey;
assert.ok(typeof kemPub === "string" && kemPub.length > 100, "initiator returns a base64 KEM public key");
assert.ok(!("kemCiphertext" in pqAdd.result), "initiator result has no ciphertext");
const pqRespAdd = JSON.parse(
  pqResp.handle(`{"apiVersion":"1","command":"addBuddy","args":{"sharedSecret":"oob","role":"responder","initiatorKemPublicKey":"${kemPub}"}}`)
);
const kemCt = pqRespAdd.result.kemCiphertext;
const kemTag = pqRespAdd.result.kemConfirmTag;
assert.ok(typeof kemCt === "string" && kemCt.length > 100, "responder returns a base64 KEM ciphertext");
assert.ok(typeof kemTag === "string" && kemTag.length > 20, "responder returns a base64 key-confirmation tag");
assert.strictEqual(pqAdd.result.pairId, pqRespAdd.result.pairId, "pairId unchanged by the KEM");
// Fail closed: matched WITHOUT the ciphertext + tag is refused (no silent classical downgrade).
const pqNoCt = JSON.parse(
  pqInit.handle(`{"apiVersion":"1","command":"confirmBuddy","args":{"pairId":"${pqAdd.result.pairId}","matched":true}}`)
);
assert.strictEqual(pqNoCt.error.code, "pq_prekey_required", "PQ confirm without ciphertext/tag refused");
// Key confirmation: a SAME-LENGTH bit-flip of the ciphertext (base64) fails closed — ML-KEM's implicit
// rejection does not throw, but the confirmation tag catches it.
const ctBuf = Buffer.from(kemCt, "base64");
ctBuf[0] ^= 0x01;
const tamperedCt = ctBuf.toString("base64");
assert.strictEqual(tamperedCt.length, kemCt.length, "tamper is same-length");
const pqTamper = JSON.parse(
  pqInit.handle(`{"apiVersion":"1","command":"confirmBuddy","args":{"pairId":"${pqAdd.result.pairId}","matched":true,"kemCiphertext":"${tamperedCt}","kemConfirmTag":"${kemTag}"}}`)
);
assert.strictEqual(pqTamper.error.code, "pq_confirm_failed", "same-length ciphertext tamper fails closed");
// With the correct ciphertext + tag the initiator completes and buddyConfirmed fires; the result also
// returns the initiator's /i confirmation tag for the app to relay to the responder.
const pqConf = JSON.parse(
  pqInit.handle(`{"apiVersion":"1","command":"confirmBuddy","args":{"pairId":"${pqAdd.result.pairId}","matched":true,"kemCiphertext":"${kemCt}","kemConfirmTag":"${kemTag}"}}`)
);
assert.strictEqual(pqConf.events[0].event, "buddyConfirmed", "PQ initiator confirms with ciphertext + tag");
const initTag = pqConf.result.initiatorConfirmTag;
assert.ok(typeof initTag === "string" && initTag.length > 20, "initiator returns a base64 /i confirmation tag");
// Bidirectional confirmation: the responder also fails closed. A matched confirm WITHOUT the initiator
// tag is refused, a tampered tag fails closed, and the correct tag confirms the responder.
const pqRespNoTag = JSON.parse(
  pqResp.handle(`{"apiVersion":"1","command":"confirmBuddy","args":{"pairId":"${pqRespAdd.result.pairId}","matched":true}}`)
);
assert.strictEqual(pqRespNoTag.error.code, "pq_prekey_required", "responder confirm without the initiator tag refused");
const itBuf = Buffer.from(initTag, "base64");
itBuf[0] ^= 0x01;
const pqRespTamper = JSON.parse(
  pqResp.handle(`{"apiVersion":"1","command":"confirmBuddy","args":{"pairId":"${pqRespAdd.result.pairId}","matched":true,"initiatorConfirmTag":"${itBuf.toString("base64")}"}}`)
);
assert.strictEqual(pqRespTamper.error.code, "pq_confirm_failed", "tampered initiator tag fails closed on the responder");
const pqRespConf = JSON.parse(
  pqResp.handle(`{"apiVersion":"1","command":"confirmBuddy","args":{"pairId":"${pqRespAdd.result.pairId}","matched":true,"initiatorConfirmTag":"${initTag}"}}`)
);
assert.strictEqual(pqRespConf.events[0].event, "buddyConfirmed", "PQ responder confirms with the initiator's /i tag");

console.log("engine-contract e2e: OK (bundle =", path.basename(bundle) + ")");
