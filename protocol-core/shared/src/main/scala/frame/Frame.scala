package frame

/** Message framing (T013, FR-015a). Every frame is exactly 256 bytes regardless of payload
  * length, so frame size leaks nothing about content (size uniformity; supports the
  * cover-traffic invariant FR-012). Layout: [2-byte big-endian length][payload][zero pad]. */
object Frame:
  val Size: Int       = 256
  val MaxPayload: Int = Size - 2 // 2-byte length prefix

  /** Pad a payload into a fixed 256-byte frame. */
  def pad(payload: Array[Byte]): Either[String, Array[Byte]] =
    if payload.length > MaxPayload then Left(s"payload ${payload.length} > max $MaxPayload")
    else
      val out = new Array[Byte](Size) // zero-filled
      out(0) = ((payload.length >> 8) & 0xff).toByte
      out(1) = (payload.length & 0xff).toByte
      System.arraycopy(payload, 0, out, 2, payload.length)
      Right(out)

  /** Recover the payload from a 256-byte frame. */
  def unpad(fr: Array[Byte]): Either[String, Array[Byte]] =
    if fr.length != Size then Left(s"frame ${fr.length} != $Size")
    else
      val len = ((fr(0) & 0xff) << 8) | (fr(1) & 0xff)
      if len > MaxPayload then Left(s"declared length $len > max $MaxPayload")
      else Right(fr.slice(2, 2 + len))

  /** A carrier (cover) frame: a 256-byte all-zero frame. The leading 2-byte length prefix is
    * 0, so it decodes to an empty payload; wire-indistinguishable in size from a real frame
    * (FR-012). Constructed directly to avoid an Option#get on the cover-traffic path. */
  def carrier(): Array[Byte] = new Array[Byte](Size)
