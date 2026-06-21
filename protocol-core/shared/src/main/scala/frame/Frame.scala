package frame

/** Message framing (T013, FR-015a). A frame is a fixed-size block regardless of payload length, so
  * frame size leaks nothing about content (size uniformity; supports the cover-traffic invariant
  * FR-012). Layout: [2-byte big-endian length][payload][zero pad].
  *
  * `Size` (256) is the default and the on-the-wire store frame size. The engine also uses a smaller
  * inner block (so that `nonce ‖ AEAD(inner)` is exactly 256 on the wire — T042); `pad`/`unpad`/
  * `carrier` therefore take an optional `size`. */
object Frame:
  val Size: Int = 256

  /** Max payload for a frame of `size` bytes (2-byte length prefix). */
  def maxPayload(size: Int = Size): Int = size - 2

  /** Max payload for a default `Size` frame. */
  val MaxPayload: Int = maxPayload(Size)

  /** Pad a payload into a fixed `size`-byte frame. */
  def pad(payload: Array[Byte], size: Int = Size): Either[String, Array[Byte]] =
    if payload.length > maxPayload(size) then
      Left(s"payload ${payload.length} > max ${maxPayload(size)}")
    else
      val out = new Array[Byte](size) // zero-filled
      out(0) = ((payload.length >> 8) & 0xff).toByte
      out(1) = (payload.length & 0xff).toByte
      System.arraycopy(payload, 0, out, 2, payload.length)
      Right(out)

  /** Recover the payload from a `size`-byte frame. */
  def unpad(fr: Array[Byte], size: Int = Size): Either[String, Array[Byte]] =
    if fr.length != size then Left(s"frame ${fr.length} != $size")
    else
      val len = ((fr(0) & 0xff) << 8) | (fr(1) & 0xff)
      if len > maxPayload(size) then Left(s"declared length $len > max ${maxPayload(size)}")
      else Right(fr.slice(2, 2 + len))

  /** A carrier (cover) frame: an all-zero `size`-byte frame. The leading 2-byte length prefix is 0,
    * so it decodes to an empty payload; wire-indistinguishable in size from a real frame (FR-012). */
  def carrier(size: Int = Size): Array[Byte] = new Array[Byte](size)
