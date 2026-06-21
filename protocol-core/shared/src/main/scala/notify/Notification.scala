package notify

/** Notification-token codec and per-client digest (T029, FR-003/FR-004). Pure, cross-compiled
  * structure only — the sealing (AEAD) lives in the JVM server, since it uses the crypto FFI.
  *
  * A receiver assigns each buddy a distinct one-hot `bitPosition` plus an aggregation `label`,
  * and hands the sealed token to that buddy at add-buddy time. A sender can therefore only ever
  * cause its OWN bit to be set; the digest reveals THAT mail waits, never WHICH buddy. */
object Notification:
  val MaxBits: Int = 512 // one bit per possible buddy (FR-015)
  val DigestBytes: Int = MaxBits / 8 // 64

  final case class NotificationToken(bitPosition: Int, label: Array[Byte]):
    require(bitPosition >= 0 && bitPosition < MaxBits, s"bit $bitPosition out of 0..${MaxBits - 1}")

  /** Plaintext layout: 8-byte big-endian round, 2-byte big-endian bit position, then the
    * aggregation label. Binding the round into the sealed plaintext stops a captured token from
    * being replayed into a DIFFERENT round (the opener validates the round matches the request). */
  def serialize(roundId: Long, t: NotificationToken): Array[Byte] =
    val out = new Array[Byte](10 + t.label.length)
    var i = 0
    while i < 8 do
      out(i) = ((roundId >>> (56 - 8 * i)) & 0xff).toByte
      i += 1
    out(8) = ((t.bitPosition >> 8) & 0xff).toByte
    out(9) = (t.bitPosition & 0xff).toByte
    System.arraycopy(t.label, 0, out, 10, t.label.length)
    out

  /** Returns the bound `(roundId, token)`. */
  def deserialize(b: Array[Byte]): Either[String, (Long, NotificationToken)] =
    if b.length < 10 then Left("token too short")
    else
      var round = 0L
      var i = 0
      while i < 8 do
        round = (round << 8) | (b(i) & 0xffL)
        i += 1
      val pos = ((b(8) & 0xff) << 8) | (b(9) & 0xff)
      if pos >= MaxBits then Left(s"bit $pos out of range")
      else Right((round, NotificationToken(pos, b.drop(10))))

  /** Fixed-size (public) bit-vector digest. Immutable; every op returns a new Digest. */
  final class Digest private (val bytes: Array[Byte]):
    def get(pos: Int): Boolean =
      require(pos >= 0 && pos < MaxBits, s"bit $pos out of 0..${MaxBits - 1}")
      (bytes(pos >> 3) & (1 << (pos & 7))) != 0
    def set(pos: Int): Digest =
      require(pos >= 0 && pos < MaxBits, s"bit $pos out of 0..${MaxBits - 1}")
      val c = bytes.clone()
      c(pos >> 3) = (c(pos >> 3) | (1 << (pos & 7))).toByte
      new Digest(c)
    def or(other: Digest): Digest =
      new Digest(bytes.zip(other.bytes).map((a, b) => (a | b).toByte))
    def isEmpty: Boolean = bytes.forall(_ == 0)
    def popcount: Int = bytes.iterator.map(b => Integer.bitCount(b & 0xff)).sum

  object Digest:
    def empty: Digest = new Digest(new Array[Byte](DigestBytes))

    /** All-zero digest emitted for traffic uniformity when a client has no waiting mail. */
    def carrier: Digest = empty
