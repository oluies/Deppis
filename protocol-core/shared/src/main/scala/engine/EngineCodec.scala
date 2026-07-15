package engine

import java.nio.charset.StandardCharsets.UTF_8
import java.util.Base64

/** JSON boundary for the engine (engine-api.md: "Messages are JSON; `apiVersion` is mandatory on
  * every call"). Dart sends a command envelope and receives a uniform response. This is the exact
  * surface the Scala.js `@JSExportTopLevel` facade exposes — keeping the wire contract identical on
  * JVM (tested here) and JS.
  *
  * Request:  `{ "apiVersion": "1", "command": "<name>", "args": { ... } }`
  * Response (success): `{ "apiVersion": "1", "result": <value|null>, "events": [ ... ] }`
  * Response (error):   `{ "apiVersion": "1", "error": { "code": "...", "message": "..." } }`
  *
  * An `apiVersion` mismatch is refused before any state changes. */
final class EngineCodec(engine: Engine):

  def handle(input: String): String =
    // The WHOLE evaluation is guarded: not just unparseable JSON, but valid-but-misshaped input
    // (a non-object envelope, a mistyped arg) must still return the uniform error envelope rather
    // than throwing a uPickle exception across the Scala.js boundary — the contract + Constitution
    // II (fixed, controlled error strings) require it.
    val out: Either[EngineError, ujson.Value] =
      try
        val env = ujson.read(input)
        val ver = env.obj.get("apiVersion").map(_.str).getOrElse("")
        if ver != EngineApi.Version then Left(EngineError("api_version", "unsupported apiVersion"))
        else dispatch(env)
      catch case _: Throwable => Left(EngineError("bad_request", "malformed request"))

    out match
      case Right(result) =>
        // Attach any events the command emitted (e.g. buddyConfirmed).
        ujson
          .Obj(
            "apiVersion" -> EngineApi.Version,
            "result" -> result,
            "events" -> ujson.Arr(engine.drainEvents().map(eventJson)*)
          )
          .render()
      case Left(EngineError(code, message)) =>
        // Discard any buffered events on the error path too, so a partially-emitted event can never
        // leak into the NEXT successful response (content-leak across calls).
        engine.drainEvents()
        ujson
          .Obj(
            "apiVersion" -> EngineApi.Version,
            "error" -> ujson.Obj("code" -> code, "message" -> message)
          )
          .render()

  private def dispatch(env: ujson.Value): Either[EngineError, ujson.Value] =
    val args = env.obj.getOrElse("args", ujson.Obj())
    env.obj.get("command").map(_.str).getOrElse("") match
      case "addBuddy" =>
        // PQ pairing prekey (US7) wire fields (all optional; base64 unless noted):
        //   in : `initiatorKemPublicKey` (responder consumes the initiator's hybrid-KEM public key),
        //        `pqPrekey: true` (an initiator opting into the PQ path — generate a keypair + defer),
        //        `pqRequired: true` (bool; the authenticated OOB PQ intent — both sides set it: binds
        //        into the safety-number derivation AND fails a responder closed with `pq_prekey_required`
        //        if the initiator's KEM public key was stripped in transit). Defaults to `false`.
        //   out: `kemPublicKey` (initiator) or `kemCiphertext` + `kemConfirmTag` (responder) — PUBLIC
        //        material the app carries out of band to the peer. Absent on the classical path. A
        //        malformed base64 value throws and is mapped to `bad_request` by the guard in `handle`.
        for
          role <- BuddyRole.parse(str(args, "role"))
          res <- engine.addBuddy(
            str(args, "sharedSecret").getBytes(UTF_8),
            role,
            initiatorKemPublicKey = optBytes(args, "initiatorKemPublicKey"),
            initiatePqPrekey = bool(args, "pqPrekey"),
            pqRequired = bool(args, "pqRequired")
          )
        yield
          val obj = ujson.Obj("pairId" -> res.pairId, "safetyNumber" -> res.safetyNumber)
          res.kemPublicKey.foreach(b => obj("kemPublicKey") = b64e(b))
          res.kemCiphertext.foreach(b => obj("kemCiphertext") = b64e(b))
          res.kemConfirmTag.foreach(b => obj("kemConfirmTag") = b64e(b))
          obj

      case "confirmBuddy" =>
        // PQ pairing confirmation is BIDIRECTIONAL (base64 wire fields):
        //   - INITIATOR: carries the responder's `kemCiphertext` + `kemConfirmTag` (the `/r` tag) back
        //     here to key-confirm + seed its deferred ratchet, and the result returns its own
        //     `initiatorConfirmTag` (the `/i` tag) for the app to relay to the responder.
        //   - RESPONDER: carries the initiator's `initiatorConfirmTag` here; it is constant-time verified
        //     before the responder confirms (fail closed on a `kemPublicKey` tampered in transit).
        // All absent/ignored on the classical path (result is then `null`).
        engine
          .confirmBuddy(
            str(args, "pairId"),
            bool(args, "matched"),
            kemCiphertext = optBytes(args, "kemCiphertext"),
            kemConfirmTag = optBytes(args, "kemConfirmTag"),
            initiatorConfirmTag = optBytes(args, "initiatorConfirmTag")
          )
          .map { res =>
            res.initiatorConfirmTag match
              case Some(tag) => ujson.Obj("initiatorConfirmTag" -> b64e(tag))
              case None => ujson.Null
          }

      case "removeBuddy" =>
        engine.removeBuddy(str(args, "pairId")).map(_ => ujson.Null)

      case "sendMessage" =>
        engine
          .sendMessage(str(args, "pairId"), str(args, "plaintext"))
          .map(n => ujson.Obj("queued" -> n))

      case "tick" =>
        engine.tick(long(args, "roundId")).map { d =>
          // Emit as a JSON number explicitly (a bare Long would render as a string). The echo shares
          // the JSON-double 2^53 ceiling; exact large round ids are carried on the string INPUT path.
          ujson.Obj(
            "roundId" -> ujson.Num(d.roundId.toDouble),
            "carrier" -> d.carrier,
            "retrieve" -> d.retrieve
          )
        }

      case "privacyStatus" =>
        Right(eventJson(engine.privacyStatus))

      case _ =>
        Left(EngineError("unknown_command", "unsupported command"))

  private def eventJson(e: EngineEvent): ujson.Value = e match
    case EngineEvent.BuddyConfirmed(pairId, safetyNumber) =>
      ujson.Obj("event" -> "buddyConfirmed", "pairId" -> pairId, "safetyNumber" -> safetyNumber)
    case EngineEvent.MessageReceived(pairId, plaintext, at) =>
      ujson.Obj(
        "event" -> "messageReceived",
        "pairId" -> pairId,
        "plaintext" -> plaintext,
        "receivedAt" -> at
      )
    case EngineEvent.Notified(roundId) =>
      ujson.Obj("event" -> "notified", "roundId" -> roundId)
    case EngineEvent.PrivacyStatus(backend, metadataPrivate, label) =>
      ujson.Obj(
        "event" -> "privacyStatus",
        "backend" -> backend,
        "metadataPrivate" -> metadataPrivate,
        "label" -> label
      )

  private def str(o: ujson.Value, k: String): String = o.obj.get(k).map(_.str).getOrElse("")
  private def bool(o: ujson.Value, k: String): Boolean = o.obj.get(k).exists(_.bool)

  /** Optional base64 byte field. Absent ⇒ None; present-but-invalid base64 throws (mapped to
    * `bad_request` by the guard in `handle`), never a silent empty. */
  private def optBytes(o: ujson.Value, k: String): Option[Array[Byte]] =
    o.obj.get(k).map(v => Base64.getDecoder.decode(v.str))

  private def b64e(b: Array[Byte]): String = Base64.getEncoder.encodeToString(b)

  /** `roundId` may arrive as a JSON number or string. JSON numbers are IEEE doubles, so a numeric
    * round id above 2^53 would silently lose precision; callers expecting large round ids should
    * send it as a string, which is parsed exactly here. A missing key defaults to 0; a value of any
    * OTHER type (boolean/null/non-numeric string) throws and is mapped to `bad_request` by the guard
    * in `handle` — never silently coerced to 0. */
  private def long(o: ujson.Value, k: String): Long = o.obj.get(k) match
    case None => 0L
    case Some(v) =>
      v.strOpt
        .map(_.toLong)
        .orElse(v.numOpt.map(_.toLong))
        .getOrElse(throw IllegalArgumentException("roundId must be a number or numeric string"))
