package crypto

import java.lang.foreign.*
import java.lang.foreign.ValueLayout.*
import java.lang.invoke.MethodHandle

/** FFM (Panama) binding to libsodium (Constitution I: call a vetted library; no hand-rolled
  * crypto). Exposes ChaCha20-Poly1305 IETF AEAD, Blake2b (`crypto_generichash`), SHA-512, the
  * ristretto255 prime-order group + its scalar field, and a constant-time compare. The native
  * library is resolved from `LIBSODIUM_PATH` or common Homebrew/system locations.
  *
  * The ristretto255 group ops are the vetted building blocks for the 2HashDH VOPRF ([[Voprf]]);
  * this object only *binds* them — the DLEQ / OPRF protocol composition lives in [[Voprf]]. */
object Sodium:
  val KeyBytes: Int = 32 // crypto_aead_chacha20poly1305_ietf_KEYBYTES
  val NpubBytes: Int = 12 // ..._NPUBBYTES (IETF nonce)
  val ABytes: Int = 16 // ..._ABYTES (Poly1305 tag)

  // ---- ristretto255 group + scalar-field sizes (libsodium `crypto_core_ristretto255_*`) ----
  val Ristretto255Bytes: Int = 32 // encoded group element (crypto_core_ristretto255_BYTES)
  val Ristretto255ScalarBytes: Int = 32 // encoded scalar (..._SCALARBYTES)
  val Ristretto255HashBytes: Int =
    64 // uniform bytes for from_hash / scalar_reduce (..._HASHBYTES / NONREDUCEDSCALARBYTES)
  val Sha512Bytes: Int = 64 // crypto_hash_sha512_BYTES

  private val linker: Linker = Linker.nativeLinker()
  private val arena: Arena = Arena.ofShared() // process-lifetime: holds the library lookup

  private val lookup: SymbolLookup =
    val candidates = sys.env.get("LIBSODIUM_PATH").toList ++ List(
      "/opt/homebrew/opt/libsodium/lib/libsodium.dylib",
      "/usr/local/opt/libsodium/lib/libsodium.dylib",
      "/opt/homebrew/lib/libsodium.dylib",
      "/usr/local/lib/libsodium.so",
      "/usr/lib/x86_64-linux-gnu/libsodium.so",
      "/usr/lib/libsodium.so"
    )
    candidates.iterator
      .flatMap(p =>
        try Some(SymbolLookup.libraryLookup(p, arena))
        catch case _: Throwable => None
      )
      .nextOption()
      .getOrElse(throw new RuntimeException("libsodium not found; set LIBSODIUM_PATH"))

  private def handle(name: String, desc: FunctionDescriptor): MethodHandle =
    val sym = lookup.find(name).orElseThrow(() => new RuntimeException(s"missing symbol $name"))
    linker.downcallHandle(sym, desc)

  private val hInit: MethodHandle = handle("sodium_init", FunctionDescriptor.of(JAVA_INT))
  private val hEncrypt: MethodHandle = handle(
    "crypto_aead_chacha20poly1305_ietf_encrypt",
    FunctionDescriptor.of(
      JAVA_INT,
      ADDRESS,
      ADDRESS,
      ADDRESS,
      JAVA_LONG,
      ADDRESS,
      JAVA_LONG,
      ADDRESS,
      ADDRESS,
      ADDRESS
    )
  )
  private val hDecrypt: MethodHandle = handle(
    "crypto_aead_chacha20poly1305_ietf_decrypt",
    FunctionDescriptor.of(
      JAVA_INT,
      ADDRESS,
      ADDRESS,
      ADDRESS,
      ADDRESS,
      JAVA_LONG,
      ADDRESS,
      JAVA_LONG,
      ADDRESS,
      ADDRESS
    )
  )
  private val hHash: MethodHandle = handle(
    "crypto_generichash",
    FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG)
  )

  // ---- ristretto255 handles ----
  // int crypto_core_ristretto255_from_hash(unsigned char *p, const unsigned char *r) — hash-to-group
  private val hR255FromHash: MethodHandle =
    handle("crypto_core_ristretto255_from_hash", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS))
  // int crypto_scalarmult_ristretto255(unsigned char *q, const unsigned char *n, const unsigned char *p) — q = n*p (rejects identity)
  private val hR255ScalarMult: MethodHandle = handle(
    "crypto_scalarmult_ristretto255",
    FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS)
  )
  // int crypto_scalarmult_ristretto255_base(unsigned char *q, const unsigned char *n) — q = n*B
  private val hR255ScalarMultBase: MethodHandle =
    handle("crypto_scalarmult_ristretto255_base", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS))
  // int crypto_core_ristretto255_is_valid_point(const unsigned char *p) — canonical, non-identity check
  private val hR255IsValidPoint: MethodHandle =
    handle("crypto_core_ristretto255_is_valid_point", FunctionDescriptor.of(JAVA_INT, ADDRESS))
  // int crypto_core_ristretto255_add(unsigned char *r, const unsigned char *p, const unsigned char *q)
  private val hR255Add: MethodHandle =
    handle(
      "crypto_core_ristretto255_add",
      FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS)
    )
  // void crypto_core_ristretto255_scalar_random(unsigned char *r)
  private val hR255ScalarRandom: MethodHandle =
    handle("crypto_core_ristretto255_scalar_random", FunctionDescriptor.ofVoid(ADDRESS))
  // int crypto_core_ristretto255_scalar_invert(unsigned char *recip, const unsigned char *s)
  private val hR255ScalarInvert: MethodHandle =
    handle(
      "crypto_core_ristretto255_scalar_invert",
      FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS)
    )
  // void crypto_core_ristretto255_scalar_mul(unsigned char *z, const unsigned char *x, const unsigned char *y)
  private val hR255ScalarMul: MethodHandle =
    handle(
      "crypto_core_ristretto255_scalar_mul",
      FunctionDescriptor.ofVoid(ADDRESS, ADDRESS, ADDRESS)
    )
  // void crypto_core_ristretto255_scalar_sub(unsigned char *z, const unsigned char *x, const unsigned char *y)
  private val hR255ScalarSub: MethodHandle =
    handle(
      "crypto_core_ristretto255_scalar_sub",
      FunctionDescriptor.ofVoid(ADDRESS, ADDRESS, ADDRESS)
    )
  // void crypto_core_ristretto255_scalar_reduce(unsigned char *r, const unsigned char *s) — 64B -> field
  private val hR255ScalarReduce: MethodHandle =
    handle("crypto_core_ristretto255_scalar_reduce", FunctionDescriptor.ofVoid(ADDRESS, ADDRESS))
  // int crypto_hash_sha512(unsigned char *out, const unsigned char *in, unsigned long long inlen)
  private val hSha512: MethodHandle =
    handle("crypto_hash_sha512", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_LONG))
  // int sodium_memcmp(const void *b1, const void *b2, size_t len) — constant time; 0 iff equal
  private val hMemcmp: MethodHandle =
    handle("sodium_memcmp", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_LONG))
  // void sodium_memzero(void *pnt, size_t len)
  private val hMemzero: MethodHandle =
    handle("sodium_memzero", FunctionDescriptor.ofVoid(ADDRESS, JAVA_LONG))

  // sodium_init returns 0 (ok), 1 (already initialised), or <0 (failure).
  // MethodHandle.invoke is signature-polymorphic: ascribe the return type with a typed val.
  private val initRc: Int = hInit.invoke()
  if initRc < 0 then throw new RuntimeException("sodium_init failed")

  private def seg(a: Arena, bytes: Array[Byte]): MemorySegment =
    if bytes.isEmpty then MemorySegment.NULL
    else
      val s = a.allocate(bytes.length.toLong)
      MemorySegment.copy(bytes, 0, s, JAVA_BYTE, 0L, bytes.length)
      s

  def aeadEncrypt(
      plaintext: Array[Byte],
      ad: Array[Byte],
      nonce: Array[Byte],
      key: Array[Byte]
  ): Array[Byte] =
    require(nonce.length == NpubBytes, s"nonce must be $NpubBytes bytes")
    require(key.length == KeyBytes, s"key must be $KeyBytes bytes")
    val a = Arena.ofConfined()
    try
      val c = a.allocate((plaintext.length + ABytes).toLong)
      val clenP = a.allocate(JAVA_LONG)
      val rc: Int = hEncrypt
        .invoke(
          c,
          clenP,
          seg(a, plaintext),
          plaintext.length.toLong,
          seg(a, ad),
          ad.length.toLong,
          MemorySegment.NULL,
          seg(a, nonce),
          seg(a, key)
        )
      if rc != 0 then throw new RuntimeException(s"aead encrypt rc=$rc")
      val outLen = clenP.get(JAVA_LONG, 0).toInt
      val out = new Array[Byte](outLen)
      MemorySegment.copy(c, JAVA_BYTE, 0L, out, 0, outLen)
      out
    finally a.close()

  def aeadDecrypt(
      ciphertext: Array[Byte],
      ad: Array[Byte],
      nonce: Array[Byte],
      key: Array[Byte]
  ): Either[String, Array[Byte]] =
    require(nonce.length == NpubBytes, s"nonce must be $NpubBytes bytes")
    require(key.length == KeyBytes, s"key must be $KeyBytes bytes")
    if ciphertext.length < ABytes then Left("ciphertext shorter than tag")
    else
      val a = Arena.ofConfined()
      try
        val m = a.allocate((ciphertext.length - ABytes).toLong + 1L)
        val mlenP = a.allocate(JAVA_LONG)
        val rc: Int = hDecrypt
          .invoke(
            m,
            mlenP,
            MemorySegment.NULL,
            seg(a, ciphertext),
            ciphertext.length.toLong,
            seg(a, ad),
            ad.length.toLong,
            seg(a, nonce),
            seg(a, key)
          )
        if rc != 0 then Left("decrypt failed (authentication)")
        else
          val outLen = mlenP.get(JAVA_LONG, 0).toInt
          val out = new Array[Byte](outLen)
          if outLen > 0 then MemorySegment.copy(m, JAVA_BYTE, 0L, out, 0, outLen)
          Right(out)
      finally a.close()

  /** Blake2b via crypto_generichash. `key` may be empty (unkeyed). */
  def blake2b(in: Array[Byte], outLen: Int, key: Array[Byte]): Array[Byte] =
    val a = Arena.ofConfined()
    try
      val out = a.allocate(outLen.toLong)
      val rc: Int = hHash
        .invoke(out, outLen.toLong, seg(a, in), in.length.toLong, seg(a, key), key.length.toLong)
      if rc != 0 then throw new RuntimeException(s"generichash rc=$rc")
      val res = new Array[Byte](outLen)
      MemorySegment.copy(out, JAVA_BYTE, 0L, res, 0, outLen)
      res
    finally a.close()

  // -------------------- ristretto255 group + scalar field --------------------
  //
  // These are thin, size-checked passthroughs to libsodium's vetted ristretto255 implementation.
  // Group elements and scalars are always the canonical 32-byte encodings. `scalar`-typed values
  // are SECRET (blinds, OPRF keys, DLEQ nonces); the native segments holding them are zeroed with
  // `sodium_memzero` in a `finally` before the confined Arena frees the page (Arena.close frees but
  // does NOT clear — Constitution II key-erasure). Returned heap arrays are the caller's to manage.

  /** Zero a secret-bearing native segment before its arena is freed (constant-time, not optimised
    * away). */
  private def memzero(s: MemorySegment, n: Int): Unit = hMemzero.invoke(s, n.toLong)

  /** Constant-time equality of two equal-length byte arrays (libsodium `sodium_memcmp`). Returns
    * `false` on a length mismatch (a public fact) without touching contents. No secret-dependent
    * branch on the bytes themselves (Constitution II). */
  def memcmp(a1: Array[Byte], a2: Array[Byte]): Boolean =
    if a1.length != a2.length then false
    else
      val a = Arena.ofConfined()
      try
        val rc: Int = hMemcmp.invoke(seg(a, a1), seg(a, a2), a1.length.toLong).asInstanceOf[Int]
        rc == 0
      finally a.close()

  /** SHA-512 of `in` (crypto_hash_sha512). Used to build 64-byte uniform strings for hash-to-group
    * and scalar reduction. */
  def sha512(in: Array[Byte]): Array[Byte] =
    val a = Arena.ofConfined()
    try
      val out = a.allocate(Sha512Bytes.toLong)
      val rc: Int = hSha512.invoke(out, seg(a, in), in.length.toLong).asInstanceOf[Int]
      if rc != 0 then throw new RuntimeException(s"crypto_hash_sha512 rc=$rc")
      val res = new Array[Byte](Sha512Bytes)
      MemorySegment.copy(out, JAVA_BYTE, 0L, res, 0, Sha512Bytes)
      res
    finally a.close()

  /** Map 64 uniform bytes to a ristretto255 group element (`crypto_core_ristretto255_from_hash`).
    * This is the vetted hash-to-group used by RFC 9497 for `H1`; NEVER hash-to-group by hand. */
  def r255FromHash(uniform64: Array[Byte]): Array[Byte] =
    require(
      uniform64.length == Ristretto255HashBytes,
      s"from_hash needs $Ristretto255HashBytes bytes"
    )
    val a = Arena.ofConfined()
    try
      val p = a.allocate(Ristretto255Bytes.toLong)
      val rc: Int = hR255FromHash.invoke(p, seg(a, uniform64)).asInstanceOf[Int]
      if rc != 0 then throw new RuntimeException(s"ristretto255_from_hash rc=$rc")
      bytesOf(p, Ristretto255Bytes)
    finally a.close()

  /** `true` iff `p` is a canonical, valid, non-identity ristretto255 encoding
    * (`crypto_core_ristretto255_is_valid_point`). */
  def r255IsValidPoint(p: Array[Byte]): Boolean =
    if p.length != Ristretto255Bytes then false
    else
      val a = Arena.ofConfined()
      try
        val rc: Int = hR255IsValidPoint.invoke(seg(a, p)).asInstanceOf[Int]
        rc == 1
      finally a.close()

  /** Scalar multiplication `q = n · p` on ristretto255 (`crypto_scalarmult_ristretto255`). `n` is a
    * SECRET scalar; its native copy is zeroed after use. Returns `None` on `rc != 0`, which
    * libsodium reports when `p` is the identity / not a valid point or `n` reduces to 0 (no
    * secret-dependent throw). */
  def r255ScalarMult(n: Array[Byte], p: Array[Byte]): Option[Array[Byte]] =
    require(n.length == Ristretto255ScalarBytes, "scalar size")
    require(p.length == Ristretto255Bytes, "point size")
    val a = Arena.ofConfined()
    val nSeg = seg(a, n)
    try
      val q = a.allocate(Ristretto255Bytes.toLong)
      val rc: Int = hR255ScalarMult.invoke(q, nSeg, seg(a, p)).asInstanceOf[Int]
      if rc != 0 then None else Some(bytesOf(q, Ristretto255Bytes))
    finally { memzero(nSeg, n.length); a.close() }

  /** Fixed-base scalar multiplication `q = n · B` (`crypto_scalarmult_ristretto255_base`), where B
    * is the group generator. `n` is SECRET; its native copy is zeroed. Returns `None` if `n`
    * reduces to 0. */
  def r255ScalarMultBase(n: Array[Byte]): Option[Array[Byte]] =
    require(n.length == Ristretto255ScalarBytes, "scalar size")
    val a = Arena.ofConfined()
    val nSeg = seg(a, n)
    try
      val q = a.allocate(Ristretto255Bytes.toLong)
      val rc: Int = hR255ScalarMultBase.invoke(q, nSeg).asInstanceOf[Int]
      if rc != 0 then None else Some(bytesOf(q, Ristretto255Bytes))
    finally { memzero(nSeg, n.length); a.close() }

  /** Group addition `r = p + q` (`crypto_core_ristretto255_add`). Both operands are public points in
    * the DLEQ transcript. Returns `None` if either encoding is invalid. */
  def r255Add(p: Array[Byte], q: Array[Byte]): Option[Array[Byte]] =
    require(p.length == Ristretto255Bytes && q.length == Ristretto255Bytes, "point size")
    val a = Arena.ofConfined()
    try
      val r = a.allocate(Ristretto255Bytes.toLong)
      val rc: Int = hR255Add.invoke(r, seg(a, p), seg(a, q)).asInstanceOf[Int]
      if rc != 0 then None else Some(bytesOf(r, Ristretto255Bytes))
    finally a.close()

  /** A uniformly random non-zero scalar (`crypto_core_ristretto255_scalar_random`). SECRET output. */
  def r255ScalarRandom(): Array[Byte] =
    val a = Arena.ofConfined()
    val s = a.allocate(Ristretto255ScalarBytes.toLong)
    try
      hR255ScalarRandom.invoke(s)
      bytesOf(s, Ristretto255ScalarBytes)
    finally { memzero(s, Ristretto255ScalarBytes); a.close() }

  /** Modular inverse `s⁻¹` in the scalar field (`crypto_core_ristretto255_scalar_invert`). `s` and
    * the result are SECRET; both native segments are zeroed. Returns `None` if `s` is 0
    * (non-invertible), reported by `rc != 0`. */
  def r255ScalarInvert(s: Array[Byte]): Option[Array[Byte]] =
    require(s.length == Ristretto255ScalarBytes, "scalar size")
    val a = Arena.ofConfined()
    val sSeg = seg(a, s)
    val recip = a.allocate(Ristretto255ScalarBytes.toLong)
    try
      val rc: Int = hR255ScalarInvert.invoke(recip, sSeg).asInstanceOf[Int]
      if rc != 0 then None else Some(bytesOf(recip, Ristretto255ScalarBytes))
    finally { memzero(sSeg, s.length); memzero(recip, Ristretto255ScalarBytes); a.close() }

  /** Scalar multiplication `z = x · y mod L` (`crypto_core_ristretto255_scalar_mul`). Result is
    * SECRET when either operand is. */
  def r255ScalarMulScalar(x: Array[Byte], y: Array[Byte]): Array[Byte] =
    require(
      x.length == Ristretto255ScalarBytes && y.length == Ristretto255ScalarBytes,
      "scalar size"
    )
    val a = Arena.ofConfined()
    val xSeg = seg(a, x); val ySeg = seg(a, y)
    val z = a.allocate(Ristretto255ScalarBytes.toLong)
    try
      hR255ScalarMul.invoke(z, xSeg, ySeg)
      bytesOf(z, Ristretto255ScalarBytes)
    finally {
      memzero(xSeg, x.length); memzero(ySeg, y.length); memzero(z, Ristretto255ScalarBytes);
      a.close()
    }

  /** Scalar subtraction `z = x − y mod L` (`crypto_core_ristretto255_scalar_sub`). Result is SECRET
    * when either operand is. */
  def r255ScalarSub(x: Array[Byte], y: Array[Byte]): Array[Byte] =
    require(
      x.length == Ristretto255ScalarBytes && y.length == Ristretto255ScalarBytes,
      "scalar size"
    )
    val a = Arena.ofConfined()
    val xSeg = seg(a, x); val ySeg = seg(a, y)
    val z = a.allocate(Ristretto255ScalarBytes.toLong)
    try
      hR255ScalarSub.invoke(z, xSeg, ySeg)
      bytesOf(z, Ristretto255ScalarBytes)
    finally {
      memzero(xSeg, x.length); memzero(ySeg, y.length); memzero(z, Ristretto255ScalarBytes);
      a.close()
    }

  /** Reduce 64 uniform bytes to a scalar mod L (`crypto_core_ristretto255_scalar_reduce`), the
    * vetted hash-to-scalar used by RFC 9497. */
  def r255ScalarReduce(uniform64: Array[Byte]): Array[Byte] =
    require(
      uniform64.length == Ristretto255HashBytes,
      s"scalar_reduce needs $Ristretto255HashBytes bytes"
    )
    val a = Arena.ofConfined()
    val s = a.allocate(Ristretto255ScalarBytes.toLong)
    try
      hR255ScalarReduce.invoke(s, seg(a, uniform64))
      bytesOf(s, Ristretto255ScalarBytes)
    finally { memzero(s, Ristretto255ScalarBytes); a.close() }

  private def bytesOf(s: MemorySegment, n: Int): Array[Byte] =
    val out = new Array[Byte](n)
    MemorySegment.copy(s, JAVA_BYTE, 0L, out, 0, n)
    out
