package cli

import java.util.Base64
import frame.Frame
import token.RetrievalToken
import schedule.Schedule
import privacy.Privacy
import privacy.Privacy.{Backend, BuildPrivacyStatus}

/** Library-first CLIs (Constitution V): JSON in (stdin) -> JSON out (stdout); errors -> stderr,
  * non-zero exit. base64 is used for byte fields. */
private def b64e(b: Array[Byte]): String = Base64.getEncoder.encodeToString(b)
private def b64d(s: String): Array[Byte] = Base64.getDecoder.decode(s)
private def fail(msg: String): Nothing =
  System.err.println(s"error: $msg")
  sys.exit(1)

/** `pcore <subcommand>` — retrieval-token | frame | deframe | schedule-next (T013/T014/T015). */
object Pcore:
  def main(args: Array[String]): Unit =
    val sub = args.headOption.getOrElse("")
    val in  = scala.io.Source.stdin.mkString
    val out: ujson.Value =
      try
        val j = if in.trim.isEmpty then ujson.Obj() else ujson.read(in)
        sub match
          case "retrieval-token" =>
            val key = j.obj.get("key").map(k => b64d(k.str)).getOrElse("dev-key".getBytes)
            val tok = RetrievalToken.derive(key, j("senderId").str, j("receiverId").str, j("counter").num.toLong)
            ujson.Obj("token" -> b64e(tok))
          case "frame" =>
            Frame.pad(b64d(j("payload").str)).fold(fail, f => ujson.Obj("frame" -> b64e(f)))
          case "deframe" =>
            Frame.unpad(b64d(j("frame").str)).fold(fail, p => ujson.Obj("payload" -> b64e(p)))
          case "schedule-next" =>
            val rid     = j.obj.get("roundId").map(_.num.toLong).getOrElse(0L)
            val payload = j.obj.get("payload").map(p => b64d(p.str))
            Schedule.planRound(rid, payload).fold(
              fail,
              plan =>
                ujson.Obj(
                  "roundId"  -> plan.roundId,
                  "kind"     -> plan.kind.toString,
                  "frame"    -> b64e(plan.frame),
                  "retrieve" -> plan.retrieve
                )
            )
          case other => fail(s"unknown subcommand: $other")
      catch case e: Throwable => fail(e.getMessage)
    println(ujson.write(out))

/** `pstatus show` — emits {backend, metadataPrivate, label}. Backend/attestation from env
  * (STORE_BACKEND, ATTESTATION_PASSED); defaults to the dev backend (no privacy). */
object Pstatus:
  def main(args: Array[String]): Unit =
    val backend = sys.env.getOrElse("STORE_BACKEND", "dev") match
      case "enclave-target" => Backend.EnclaveTarget
      case "groove-target"  => Backend.GrooveTarget
      case "groove-stub"    => Backend.GrooveStub
      case _                => Backend.Dev
    val status = BuildPrivacyStatus(backend, sys.env.get("ATTESTATION_PASSED").contains("true"))
    println(
      ujson.write(
        ujson.Obj(
          "backend"         -> backend.toString,
          "metadataPrivate" -> status.metadataPrivate,
          "label"           -> status.label
        )
      )
    )
