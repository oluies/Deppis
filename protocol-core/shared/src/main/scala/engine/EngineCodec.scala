package engine

import java.nio.charset.StandardCharsets.UTF_8

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
    val parsed =
      try Right(ujson.read(input))
      catch case _: Throwable => Left(EngineError("bad_request", "malformed JSON envelope"))

    val out = parsed.flatMap { env =>
      val ver = env.obj.get("apiVersion").map(_.str).getOrElse("")
      if ver != EngineApi.Version then
        Left(EngineError("api_version", "unsupported apiVersion"))
      else dispatch(env)
    }

    out match
      case Right(result) =>
        // Attach any events the command emitted (e.g. buddyConfirmed).
        ujson.Obj(
          "apiVersion" -> EngineApi.Version,
          "result"     -> result,
          "events"     -> ujson.Arr(engine.drainEvents().map(eventJson)*)
        ).render()
      case Left(EngineError(code, message)) =>
        ujson.Obj(
          "apiVersion" -> EngineApi.Version,
          "error"      -> ujson.Obj("code" -> code, "message" -> message)
        ).render()

  private def dispatch(env: ujson.Value): Either[EngineError, ujson.Value] =
    val args = env.obj.getOrElse("args", ujson.Obj())
    env.obj.get("command").map(_.str).getOrElse("") match
      case "addBuddy" =>
        for
          role <- BuddyRole.parse(str(args, "role"))
          res  <- engine.addBuddy(str(args, "sharedSecret").getBytes(UTF_8), role)
        yield ujson.Obj("pairId" -> res.pairId, "safetyNumber" -> res.safetyNumber)

      case "confirmBuddy" =>
        engine.confirmBuddy(str(args, "pairId"), bool(args, "matched")).map(_ => ujson.Null)

      case "removeBuddy" =>
        engine.removeBuddy(str(args, "pairId")).map(_ => ujson.Null)

      case "sendMessage" =>
        engine.sendMessage(str(args, "pairId"), str(args, "plaintext"))
          .map(n => ujson.Obj("queued" -> n))

      case "tick" =>
        engine.tick(long(args, "roundId")).map { d =>
          ujson.Obj("roundId" -> d.roundId, "carrier" -> d.carrier, "retrieve" -> d.retrieve)
        }

      case "privacyStatus" =>
        Right(eventJson(engine.privacyStatus))

      case other =>
        Left(EngineError("unknown_command", s"unsupported command"))

  private def eventJson(e: EngineEvent): ujson.Value = e match
    case EngineEvent.BuddyConfirmed(pairId, safetyNumber) =>
      ujson.Obj("event" -> "buddyConfirmed", "pairId" -> pairId, "safetyNumber" -> safetyNumber)
    case EngineEvent.MessageReceived(pairId, plaintext, at) =>
      ujson.Obj("event" -> "messageReceived", "pairId" -> pairId, "plaintext" -> plaintext, "receivedAt" -> at)
    case EngineEvent.Notified(roundId) =>
      ujson.Obj("event" -> "notified", "roundId" -> roundId)
    case EngineEvent.PrivacyStatus(backend, metadataPrivate, label) =>
      ujson.Obj("event" -> "privacyStatus", "backend" -> backend, "metadataPrivate" -> metadataPrivate, "label" -> label)

  private def str(o: ujson.Value, k: String): String  = o.obj.get(k).map(_.str).getOrElse("")
  private def bool(o: ujson.Value, k: String): Boolean = o.obj.get(k).exists(_.bool)
  private def long(o: ujson.Value, k: String): Long    = o.obj.get(k).map(_.num.toLong).getOrElse(0L)
