// Provider-routing bridge for the native (flutter_js) engine — the native counterpart of the web
// client's js_interop bridge (lib/provider/routing_web.dart).
//
// The bundle's `ProviderSession` calls a host `JsProviderApi` whose methods return Promises; a
// browser implements them directly over gRPC-web. An embedded runtime (JavaScriptCore on iOS,
// QuickJS on Android) cannot await Dart, so the two sides exchange MESSAGES instead:
//
//   JS → host  `send(json)`  (flutter_js `sendMessage`), one of
//     { t: 'call', dev, id, method, args }   a provider RPC; the host answers with __providerReply
//     { t: 'done', dev, id, ok, value }      a session call (__sessionRun) settled
//   host → JS  evaluated code
//     __routedNew(dev, user, label, tuning)  a routed engine + session for device `dev`
//     __engineHandle(dev, request)           that engine's engine-api `handle` (synchronous)
//     __providerReply(id, result)            resolves the RPC's Promise (`result` already in JS shape)
//     __sessionRun(dev, id, method, arg)     runs session[method](arg); answers with a 'done'
//
// One runtime can host several devices (`dev` = a small integer the host picks): the app runs one,
// the simulator self-test two. Several flutter_js runtimes in one app do NOT work — on
// JavaScriptCore its `sendMessage` callback is a static, so every runtime's messages reach the
// most recently created one.
//
// Only opaque bytes cross (base64 here; Uint8Array inside), never plaintext or keys. A host fault
// resolves to the RPC's safe answer on the Dart side, so nothing here ever rejects a provider
// Promise; the Scala.js port would treat a rejection the same way anyway.
//
// Single source of truth: `engine_factory_io.dart` loads this exact file, and the Dart VM test
// (test/routing_native_test.dart) drives it, with the real bundle, under Node.
globalThis.__installProviderBridge = function (send) {
  var T = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  var lut = {};
  for (var i = 0; i < T.length; i++) lut[T.charAt(i)] = i;

  // atob/btoa are absent in JavaScriptCore and QuickJS.
  function decode(s) {
    var clean = s.replace(/=+$/, '');
    var out = new Uint8Array((clean.length * 6) >> 3);
    var acc = 0, bits = 0, o = 0;
    for (var j = 0; j < clean.length; j++) {
      acc = ((acc << 6) | lut[clean.charAt(j)]) & 0xffffff;
      bits += 6;
      if (bits >= 8) { bits -= 8; out[o++] = (acc >> bits) & 0xff; }
    }
    return out;
  }
  function encode(b) {
    var out = '';
    for (var j = 0; j < b.length; j += 3) {
      var n = (b[j] << 16) | ((j + 1 < b.length ? b[j + 1] : 0) << 8) | (j + 2 < b.length ? b[j + 2] : 0);
      out += T.charAt((n >> 18) & 63) + T.charAt((n >> 12) & 63) +
        (j + 1 < b.length ? T.charAt((n >> 6) & 63) : '=') +
        (j + 2 < b.length ? T.charAt(n & 63) : '=');
    }
    return out;
  }

  function signal(s) { return { label: encode(s.label), bit: s.bit }; }
  function ops(o) {
    return {
      roundId: o.roundId,
      writeToken: encode(o.writeToken),
      frame: encode(o.frame),
      signal: signal(o.signal),
      fallbackSignal: signal(o.fallbackSignal),
      readToken: encode(o.readToken)
    };
  }

  var pending = {};
  var next = 0;
  var devices = {};
  function same(r) { return r; }

  function apiFor(dev) {
    function call(method, args, fromHost) {
      return new Promise(function (resolve) {
        var id = ++next;
        pending[id] = function (r) { resolve(fromHost(r)); };
        send(JSON.stringify({ t: 'call', dev: dev, id: id, method: method, args: args }));
      });
    }
    return {
      register: function (user, label) {
        return call('register', [user, encode(label)], same);
      },
      uploadBundle: function (user, fromRound, slots) {
        var out = [];
        for (var k = 0; k < slots.length; k++) out.push(ops(slots[k]));
        return call('uploadBundle', [user, fromRound, out], same);
      },
      getDigest: function (user, roundId) {
        return call('getDigest', [user, roundId], function (r) { return r == null ? null : decode(r); });
      },
      submitLive: function (user, o) {
        return call('submitLive', [user, ops(o)], same);
      },
      collectReceipt: function (user, roundId) {
        return call('collectReceipt', [user, roundId], function (r) {
          if (r == null) return null;
          return {
            roundId: r.roundId,
            ranLive: r.ranLive,
            writeAccepted: r.writeAccepted,
            retrieved: r.retrieved == null ? null : decode(r.retrieved)
          };
        });
      },
      collectAll: function (user) {
        return call('collectAll', [user], same);
      }
    };
  }

  globalThis.__providerReply = function (id, result) {
    var k = pending[id];
    if (k) { delete pending[id]; k(result); }
  };

  // Device `dev`: a PROVIDER-ROUTED engine (no transport of its own, just its notify label) and
  // `new ProviderSession(engine, api, user, label[, tuning…])`; tuning is an array (the
  // ProviderSession constructor's trailing arguments, in order) or null for the defaults.
  globalThis.__routedNew = function (dev, user, labelB64, tuning) {
    var label = decode(labelB64);
    var engine = new globalThis.ProtocolEngine(null, label);
    var args = [engine, apiFor(dev), user, label];
    if (tuning) args = args.concat(tuning);
    var S = globalThis.ProviderSession;
    devices[dev] = { engine: engine, session: new (Function.prototype.bind.apply(S, [null].concat(args)))() };
  };

  globalThis.__engineHandle = function (dev, request) {
    return devices[dev].engine.handle(request);
  };

  globalThis.__sessionRun = function (dev, id, method, arg) {
    var p;
    try { p = devices[dev].session[method](arg); } catch (e) { p = Promise.reject(e); }
    Promise.resolve(p).then(
      function (v) { send(JSON.stringify({ t: 'done', dev: dev, id: id, ok: true, value: v === undefined ? null : v })); },
      function () { send(JSON.stringify({ t: 'done', dev: dev, id: id, ok: false, value: null })); }
    );
  };
};
