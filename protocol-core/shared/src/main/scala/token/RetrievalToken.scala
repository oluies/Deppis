package token

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.nio.charset.StandardCharsets.UTF_8

/** Retrieval-token PRF (T014, FR-014). Token = HMAC-SHA256_key(senderId ‖ receiverId ‖
  * counter), each field length-prefixed for unambiguous domain separation.
  *
  * HMAC-SHA256 is taken from the JCA (a vetted platform primitive) — NOT hand-rolled
  * (Constitution I; T014 explicitly permits "Blake2b or HMAC"). Non-recurrence (FR-014)
  * follows from the monotone per-message counter: each (sender, receiver, counter) maps to a
  * distinct token, so a token is never reused for two messages. */
object RetrievalToken:
  val Length: Int = 32

  def derive(key: Array[Byte], senderId: String, receiverId: String, counter: Long): Array[Byte] =
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(new SecretKeySpec(key, "HmacSHA256"))
    mac.update(lengthPrefixed(senderId.getBytes(UTF_8)))
    mac.update(lengthPrefixed(receiverId.getBytes(UTF_8)))
    mac.update(longBytes(counter))
    mac.doFinal()

  /** Constant-time comparison — no secret-dependent early exit (Constitution II). */
  def equalsCT(a: Array[Byte], b: Array[Byte]): Boolean = MessageDigest.isEqual(a, b)

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
