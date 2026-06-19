package notify

/** Notification-token codec and per-client digest (T029, FR-003/FR-004). Pure, cross-compiled
  * structure only — the sealing (AEAD) lives in the JVM server, since it uses the crypto FFI.
  *
  * A receiver assigns each buddy a distinct one-hot `bitPosition` plus an aggregation `label`,
  * and hands the sealed token to that buddy at add-buddy time. A sender can therefore only ever
  * cause its OWN bit to be set; the digest reveals THAT mail waits, never WHICH buddy. */
object Notification:
  val MaxBits: Int     = 512        // one bit per possible buddy (FR-015)
  val DigestBytes: Int = MaxBits / 8 // 64

  final case class NotificationToken(bitPosition: Int, label: Array[Byte]):
    require(bitPosition >= 0 && bitPosition < MaxBits, s"bit $bitPosition out of 0..${MaxBits - 1}")

  /** 2-byte big-endian bit position, then the aggregation label. */
  def serialize(t: NotificationToken): Array[Byte] =
    val out = new Array[Byte](2 + t.label.length)
    out(0) = ((t.bitPosition >> 8) & 0xff).toByte
    out(1) = (t.bitPosition & 0xff).toByte
    System.arraycopy(t.label, 0, out, 2, t.label.length)
    out

  def deserialize(b: Array[Byte]): Either[String, NotificationToken] =
    if b.length < 2 then Left("token too short")
    else
      val pos = ((b(0) & 0xff) << 8) | (b(1) & 0xff)
      if pos >= MaxBits then Left(s"bit $pos out of range")
      else Right(NotificationToken(pos, b.drop(2)))

  /** Fixed-size (public) bit-vector digest. Immutable; every op returns a new Digest. */
  final class Digest private (val bytes: Array[Byte]):
    def get(pos: Int): Boolean = (bytes(pos >> 3) & (1 << (pos & 7))) != 0
    def set(pos: Int): Digest =
      val c = bytes.clone()
      c(pos >> 3) = (c(pos >> 3) | (1 << (pos & 7))).toByte
      new Digest(c)
    def or(other: Digest): Digest =
      new Digest(bytes.zip(other.bytes).map((a, b) => (a | b).toByte))
    def isEmpty: Boolean      = bytes.forall(_ == 0)
    def popcount: Int         = bytes.iterator.map(b => Integer.bitCount(b & 0xff)).sum

  object Digest:
    def empty: Digest   = new Digest(new Array[Byte](DigestBytes))
    /** All-zero digest emitted for traffic uniformity when a client has no waiting mail. */
    def carrier: Digest = empty
