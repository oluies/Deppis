// Minimal gRPC-web client (no generated stubs): POST a WriteBatch(round_id=N) request to Envoy as
// gRPC-web (HTTP/1.1) and assert the server's gRPC (HTTP/2) WriteBatchResponse comes back with the
// round_id echoed and grpc-status: 0. This proves the browser→Envoy→server hop end to end (T032c):
// Envoy's grpc_web filter translates this HTTP/1.1 request into upstream HTTP/2 gRPC and frames the
// reply back. No libsodium / no crypto on this path — the ObliviousStore is a pure byte store.
const http = require('http');

const ENVOY = process.env.ENVOY || 'http://envoy:8080';
const PATH = '/metadatamessenger.store.v1.ObliviousStore/WriteBatch';
const ROUND = 42;

function varint(n) { const o = []; while (n > 127) { o.push((n & 0x7f) | 0x80); n >>>= 7; } o.push(n); return o; }
function be32(n) { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0); return b; }

// WriteBatchRequest { round_id = 1 (uint64) } → field 1 varint: tag 0x08, then the value.
const msg = Buffer.from([0x08, ...varint(ROUND)]);
// gRPC-web frame = [flags(1)=0][len(4, BE)][message].
const frame = Buffer.concat([Buffer.from([0x00]), be32(msg.length), msg]);

// Parse a gRPC-web body into its frames: each = [flags(1)][len(4 BE)][bytes]. flags&0x80 ⇒ trailers.
function parseFrames(body) {
  const out = []; let i = 0;
  while (i + 5 <= body.length) {
    const flags = body[i]; const len = body.readUInt32BE(i + 1);
    const data = body.slice(i + 5, i + 5 + len); i += 5 + len;
    out.push({ trailer: (flags & 0x80) !== 0, data });
  }
  return out;
}

function attempt() {
  return new Promise((resolve, reject) => {
    const url = new URL(PATH, ENVOY);
    const req = http.request(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/grpc-web+proto',
        'x-grpc-web': '1',
        'accept': 'application/grpc-web+proto',
        'content-length': frame.length,
      },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const body = Buffer.concat(chunks);
        const frames = parseFrames(body);
        // grpc-status may arrive as an HTTP header (trailers-only via Envoy) or a trailer frame.
        const hdrStatus = res.headers['grpc-status'];
        const trailer = frames.find((f) => f.trailer);
        const trailerStr = trailer ? trailer.data.toString('utf8') : '';
        const statusOk = hdrStatus === '0' || hdrStatus === undefined && (trailerStr.includes('grpc-status:0') || trailerStr.includes('grpc-status: 0'));
        const dataFrame = frames.find((f) => !f.trailer);
        if (!dataFrame) return reject(new Error(`no data frame; status hdr=${hdrStatus} trailer="${trailerStr}" body=${body.toString('hex')}`));
        const p = dataFrame.data; // WriteBatchResponse { round_id = 1 } → 0x08 <varint>
        if (p[0] === 0x08 && p[1] === ROUND && statusOk) {
          console.log(`GRPC-WEB-ROUNDTRIP-OK: WriteBatch(round_id=${ROUND}) echoed through Envoy; grpc-status ok`);
          return resolve(true);
        }
        reject(new Error(`unexpected: payload=${p.toString('hex')} statusHdr=${hdrStatus} trailer="${trailerStr}"`));
      });
    });
    req.on('error', reject);
    req.write(frame); req.end();
  });
}

(async () => {
  // Retry: the client may race Envoy/server startup in compose.
  for (let i = 1; i <= 30; i++) {
    try { await attempt(); process.exit(0); }
    catch (e) { console.error(`[try ${i}/30] ${e.message}`); await new Promise((r) => setTimeout(r, 2000)); }
  }
  console.error('GRPC-WEB-ROUNDTRIP-FAIL: exhausted retries');
  process.exit(1);
})();
