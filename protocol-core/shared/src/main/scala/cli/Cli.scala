package cli

import java.util.Base64
import frame.Frame
import token.RetrievalToken
import schedule.Schedule
import handshake.Handshake
import privacy.Privacy
import privacy.Privacy.{Backend, BuildPrivacyStatus}

/** Library-first CLIs (Constitution V): JSON in (stdin) -> JSON out (stdout); errors -> stderr,
  * non-zero exit. base64 is used for byte fields. */
private def b64e(b: Array[Byte]): String = Base64.getEncoder.encodeToString(b)
private def b64d(s: String): Array[Byte] = Base64.getDecoder.decode(s)
private def fail(msg: String): Nothing =
  System.err.println(s"error: $msg")
  sys.exit(1)

/** Parse a JSON counter as an exact 64-bit Long. JSON numbers are Doubles in upickle and lose
  * integer precision above 2^53, which would weaken retrieval-token non-recurrence (FR-014);
  * pass the counter as a JSON string to preserve the full range. */
private def exactLong(v: ujson.Value): Long = v match
  case ujson.Str(s) => s.toLong
  case other => other.num.toLong

/** `pcore <subcommand>` — retrieval-token | frame | deframe | schedule-next (T013/T014/T015). */
object Pcore:
  /** Pure command core: `(subcommand, stdin JSON) -> Right(result) | Left(error)`. Holds no IO so
    * it is directly unit-testable; `main` is the thin stdin/stdout/exit shell around it. Any thrown
    * exception (bad JSON, missing key, bad base64) maps to a `Left` rather than escaping. */
  def run(sub: String, in: String): Either[String, ujson.Value] =
    try
      val j = if in.trim.isEmpty then ujson.Obj() else ujson.read(in)
      sub match
        case "handshake-init" =>
          // Optional `pqRequired` (bool, default false) — the authenticated OOB PQ intent (US7). It is
          // threaded into the derivation so the CLI emits the SAME pairId/safetyNumber the engine does
          // for a PQ-required pairing; omitting it (or false) reproduces the classical values byte for
          // byte (backward compatible).
          //
          // FAIL LOUD on a typo'd key: `pqRequired` is a SECURITY intent flag, so a misspelling
          // (`pq_required`, `pqrequired`, …) must NOT silently fall back to the classical derivation
          // (the silent-non-PQ failure mode). Reject any key outside the accepted set rather than
          // ignoring it (Left, consistent with the CLI's existing malformed-input handling). Scoped to
          // this CLI input only — EngineCodec's lenient codec is a separate, pre-existing pattern.
          val allowed = Set("sharedSecret", "pqRequired")
          val unknown = j.obj.keysIterator.filterNot(allowed).toVector.sorted
          if unknown.nonEmpty then
            throw IllegalArgumentException(s"unknown arg(s): ${unknown.mkString(", ")}")
          val pqRequired = j.obj.get("pqRequired").exists(_.bool)
          val pi = Handshake.init(b64d(j("sharedSecret").str), pqRequired)
          Right(
            ujson.Obj(
              "pairId" -> pi.pairId,
              "safetyNumber" -> pi.safetyNumber,
              "pairKey" -> b64e(pi.pairKey)
            )
          )
        case "retrieval-token" =>
          val key = j.obj.get("key").map(k => b64d(k.str)).getOrElse("dev-key".getBytes)
          val tok = RetrievalToken.derive(
            key,
            j("senderId").str,
            j("receiverId").str,
            exactLong(j("counter"))
          )
          Right(ujson.Obj("token" -> b64e(tok)))
        case "frame" =>
          Frame.pad(b64d(j("payload").str)).map(f => ujson.Obj("frame" -> b64e(f)))
        case "deframe" =>
          Frame.unpad(b64d(j("frame").str)).map(p => ujson.Obj("payload" -> b64e(p)))
        case "schedule-next" =>
          val rid = j.obj.get("roundId").map(_.num.toLong).getOrElse(0L)
          val payload = j.obj.get("payload").map(p => b64d(p.str))
          Schedule.planRound(rid, payload).map { plan =>
            ujson.Obj(
              "roundId" -> plan.roundId,
              "kind" -> plan.kind.toString,
              "frame" -> b64e(plan.frame),
              "retrieve" -> plan.retrieve
            )
          }
        case other => Left(s"unknown subcommand: $other")
    catch case e: Throwable => Left(Option(e.getMessage).getOrElse(e.getClass.getSimpleName))

  def main(args: Array[String]): Unit =
    val sub = args.headOption.getOrElse("")
    val in = scala.io.Source.stdin.mkString
    run(sub, in).fold(fail, out => println(ujson.write(out)))

/** `pstatus show` — emits {backend, metadataPrivate, label}. Backend/attestation from env
  * (STORE_BACKEND, ATTESTATION_PASSED); defaults to the dev backend (no privacy). */
object Pstatus:
  /** Pure core: derives the privacy-status JSON from an environment map (so tests can supply env
    * without mutating the process). `main` calls it with `sys.env`. */
  def run(env: Map[String, String]): ujson.Value =
    val backend = env.getOrElse("STORE_BACKEND", "dev") match
      case "enclave-target" => Backend.EnclaveTarget
      case "groove-target" => Backend.GrooveTarget
      case "groove-stub" => Backend.GrooveStub
      case _ => Backend.Dev
    val status = BuildPrivacyStatus(backend, env.get("ATTESTATION_PASSED").contains("true"))
    ujson.Obj(
      "backend" -> backend.toString,
      "metadataPrivate" -> status.metadataPrivate,
      "label" -> status.label
    )

  def main(args: Array[String]): Unit =
    println(ujson.write(run(sys.env)))
