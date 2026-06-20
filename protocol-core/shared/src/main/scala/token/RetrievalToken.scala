package token

import kdf.Kdf
import java.nio.charset.StandardCharsets.UTF_8

/** Retrieval-token PRF (T014, FR-014). Token = HMAC-SHA256_key(senderId ‖ receiverId ‖
  * counter), each field length-prefixed for unambiguous domain separation.
  *
  * HMAC-SHA256 comes from the platform-split [[kdf.Kdf]] (JVM = JCA, JS = @noble/hashes) — a vetted
  * primitive, NOT hand-rolled (Constitution I; T014 permits "Blake2b or HMAC"). Routing through
  * `Kdf` keeps this PRF cross-compilable (the client engine derives tokens on JS too). Non-recurrence
  * (FR-014) follows from the monotone per-message counter: each (sender, receiver, counter) maps to
  * a distinct token, so a token is never reused for two messages. */
object RetrievalToken:
  val Length: Int = 32

  def derive(key: Array[Byte], senderId: String, receiverId: String, counter: Long): Array[Byte] =
    Kdf.hmacSha256(
      key,
      lengthPrefixed(senderId.getBytes(UTF_8)) ++ lengthPrefixed(receiverId.getBytes(UTF_8)) ++ longBytes(counter)
    )

  /** Constant-time comparison — no secret-dependent early exit (Constitution II). Length is public,
    * so a length mismatch may short-circuit; equal-length content is compared in constant time. A
    * byte compare is not a crypto primitive, so a direct implementation is fine here. */
  def equalsCT(a: Array[Byte], b: Array[Byte]): Boolean =
    if a.length != b.length then false
    else
      var diff = 0
      var i    = 0
      while i < a.length do
        diff |= (a(i) ^ b(i))
        i += 1
      diff == 0

  private def lengthPrefixed(b: Array[Byte]): Array[Byte] = longBytes(b.length.toLong) ++ b

  private def longBytes(v: Long): Array[Byte] =
    val out = new Array[Byte](8)
    var x   = v
    var i   = 7
    while i >= 0 do
      out(i) = (x & 0xff).toByte
      x >>= 8
      i -= 1
    out
