package crypto

/** Unambiguous byte-string framing shared by the VOPRF protocol composition. Domain separation and
  * transcript hashing rely on the property that distinct tuples of byte strings never produce the
  * same concatenation; a single canonical encoder guarantees both [[Voprf]] and [[EpochEvolution]]
  * frame their inputs identically (a divergence would silently reintroduce collisions). */
private[crypto] object Encoding:

  /** Concatenate `parts` with a 4-byte big-endian length prefix before each element, so that
    * `lengthPrefixed(a, b) == lengthPrefixed(a', b')` implies `a == a' && b == b'` (no re-splitting
    * ambiguity). Each element must be < 2^32 bytes (always true for our inputs). */
  def lengthPrefixed(parts: Array[Byte]*): Array[Byte] =
    val out = new java.io.ByteArrayOutputStream()
    parts.foreach { p =>
      val len = p.length
      out.write((len >>> 24) & 0xff)
      out.write((len >>> 16) & 0xff)
      out.write((len >>> 8) & 0xff)
      out.write(len & 0xff)
      out.write(p)
    }
    out.toByteArray
