package kdf

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** Thin keyed-derivation helper over the JCA's HMAC-SHA256 (a vetted primitive — Constitution
  * I, not hand-rolled). Used to derive per-pair identifiers and keys from the out-of-band
  * shared secret. */
object Kdf:
  def hmacSha256(key: Array[Byte], info: Array[Byte]): Array[Byte] =
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(new SecretKeySpec(key, "HmacSHA256"))
    mac.update(info)
    mac.doFinal()
