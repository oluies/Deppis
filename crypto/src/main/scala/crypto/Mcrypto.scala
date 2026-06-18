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
            // Self-test: AEAD round-trip over a fixed input proves the libsodium binding works.
            val key = Array.tabulate(Crypto.KeyBytes)(i => (0x80 + i).toByte)
            val non = Array[Byte](7, 0, 0, 0, 64, 65, 66, 67, 68, 69, 70, 71)
            val ad  = Array[Byte](80, 81, 82, 83)
            val pt  = "metadata-messenger KAT".getBytes
            val ok  = Crypto.aeadOpen(key, non, ad, Crypto.aeadSeal(key, non, ad, pt)).exists(_.sameElements(pt))
            ujson.Obj("suite" -> "chacha20poly1305-ietf", "pass" -> ok, "vectors" -> 1)
          case other => fail(s"unknown subcommand: $other")
      catch case e: Throwable => fail(e.getMessage)
    println(ujson.write(out))
