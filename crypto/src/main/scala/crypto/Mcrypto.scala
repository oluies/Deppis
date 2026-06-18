package crypto

import java.util.Base64

/** `mcrypto` CLI (Constitution V): JSON in (stdin) -> JSON out (stdout); errors -> stderr.
  * Subcommands: aead-seal | aead-open | kdf | kat. Byte fields are base64. */
object Mcrypto:
  private def b64e(b: Array[Byte]): String       = Base64.getEncoder.encodeToString(b)
  private def b64d(s: String): Array[Byte]       = Base64.getDecoder.decode(s)
  private def optBytes(j: ujson.Value, k: String): Array[Byte] =
    j.obj.get(k).map(v => b64d(v.str)).getOrElse(Array.emptyByteArray)
  private def fail(msg: String): Nothing =
    System.err.println(s"error: $msg"); sys.exit(1)
  private def hex(s: String): Array[Byte] =
    s.grouped(2).map(Integer.parseInt(_, 16).toByte).toArray

  def main(args: Array[String]): Unit =
    val sub = args.headOption.getOrElse("")
    val in  = scala.io.Source.stdin.mkString
    val out: ujson.Value =
      try
        val j = if in.trim.isEmpty then ujson.Obj() else ujson.read(in)
        sub match
          case "aead-seal" =>
            val ct = Crypto.aeadSeal(b64d(j("key").str), b64d(j("nonce").str), optBytes(j, "ad"), b64d(j("plaintext").str))
            ujson.Obj("ciphertext" -> b64e(ct))
          case "aead-open" =>
            Crypto.aeadOpen(b64d(j("key").str), b64d(j("nonce").str), optBytes(j, "ad"), b64d(j("ciphertext").str))
              .fold(fail, pt => ujson.Obj("plaintext" -> b64e(pt)))
          case "kdf" =>
            val okm = Crypto.kdf(b64d(j("ikm").str), optBytes(j, "salt"), optBytes(j, "info"), j("len").num.toInt)
            ujson.Obj("okm" -> b64e(okm))
          case "kat" =>
            // Real published vector: RFC 7693 BLAKE2b-512("abc").
            val rfc7693 = hex(
              "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1" +
                "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
            )
            val pass = Crypto.blake2b("abc".getBytes, 64).sameElements(rfc7693)
            ujson.Obj("suite" -> "blake2b-512 (RFC 7693)", "pass" -> pass, "vectors" -> 1)
          case other => fail(s"unknown subcommand: $other")
      catch case e: Throwable => fail(e.getMessage)
    println(ujson.write(out))
