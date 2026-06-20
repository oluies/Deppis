package random

import java.security.SecureRandom

/** Cryptographically-strong randomness (JVM). Used for per-session cover-traffic keys so cover
  * (carrier) retrieval tokens are unlinkable and indistinguishable from real ones (FR-012). The JS
  * platform provides the same `bytes` via Web Crypto `getRandomValues` (both synchronous). */
object Rand:
  private val sr = new SecureRandom()

  def bytes(n: Int): Array[Byte] =
    val b = new Array[Byte](n)
    sr.nextBytes(b)
    b
