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

  /** Pure command core: `(subcommand, stdin JSON) -> Right(result) | Left(error)`. Holds no IO so
    * it is directly unit-testable; `main` is the thin stdin/stdout/exit shell around it. Any thrown
    * exception (bad JSON, missing key, bad base64) maps to a `Left` rather than escaping. */
  def run(sub: String, in: String): Either[String, ujson.Value] =
    try
      val j = if in.trim.isEmpty then ujson.Obj() else ujson.read(in)
      sub match
        case "aead-seal" =>
          val ct = Crypto.aeadSeal(b64d(j("key").str), b64d(j("nonce").str), optBytes(j, "ad"), b64d(j("plaintext").str))
          Right(ujson.Obj("ciphertext" -> b64e(ct)))
        case "aead-open" =>
          Crypto.aeadOpen(b64d(j("key").str), b64d(j("nonce").str), optBytes(j, "ad"), b64d(j("ciphertext").str))
            .map(pt => ujson.Obj("plaintext" -> b64e(pt)))
        case "kdf" =>
          val okm = Crypto.kdf(b64d(j("ikm").str), optBytes(j, "salt"), optBytes(j, "info"), j("len").num.toInt)
          Right(ujson.Obj("okm" -> b64e(okm)))
        case "kat" =>
          // Two published static vectors: RFC 7693 Blake2b + RFC 8439 ChaCha20-Poly1305.
          val blakeOk = Crypto.blake2b("abc".getBytes, 64).sameElements(Kat.Blake2b512Abc)
          val aeadOk = Crypto
            .aeadSeal(Kat.Rfc8439.key, Kat.Rfc8439.nonce, Kat.Rfc8439.aad, Kat.Rfc8439.plaintext)
            .sameElements(Kat.Rfc8439.ciphertext)
          Right(
            ujson.Obj(
              "suites"  -> ujson.Arr("blake2b-512 (RFC 7693)", "chacha20poly1305-ietf (RFC 8439)"),
              "pass"    -> (blakeOk && aeadOk),
              "vectors" -> 2
            )
          )
        case other => Left(s"unknown subcommand: $other")
    catch case e: Throwable => Left(Option(e.getMessage).getOrElse(e.getClass.getSimpleName))

  def main(args: Array[String]): Unit =
    val sub = args.headOption.getOrElse("")
    val in  = scala.io.Source.stdin.mkString
    run(sub, in).fold(fail, out => println(ujson.write(out)))
