package aead

import javax.crypto.Cipher
import javax.crypto.spec.{IvParameterSpec, SecretKeySpec}

/** ChaCha20-Poly1305 AEAD (JVM, via the JCA — a vetted platform primitive, NOT hand-rolled,
  * Constitution I). RFC 8439 IETF construction: 32-byte key, 12-byte nonce, 16-byte appended tag,
  * no AAD. The JS platform provides the same via `@noble/ciphers` (both synchronous), so the
  * cross-compiled engine encrypts frames identically on JVM and JS. Used to make every wire frame —
  * real or carrier — uniform random-looking bytes (T042). */
object Aead:
  val KeyBytes: Int = 32
  val NonceBytes: Int = 12
  val TagBytes: Int = 16

  /** Encrypt: returns `ciphertext ‖ tag` (plaintext.length + 16). */
  def seal(key: Array[Byte], nonce: Array[Byte], plaintext: Array[Byte]): Array[Byte] =
    val c = Cipher.getInstance("ChaCha20-Poly1305")
    c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ChaCha20"), new IvParameterSpec(nonce))
    c.doFinal(plaintext)

  /** Decrypt + verify; `None` on authentication failure (never a secret-dependent message). */
  def open(key: Array[Byte], nonce: Array[Byte], ciphertext: Array[Byte]): Option[Array[Byte]] =
    try
      val c = Cipher.getInstance("ChaCha20-Poly1305")
      c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "ChaCha20"), new IvParameterSpec(nonce))
      Some(c.doFinal(ciphertext))
    catch case _: Throwable => None
