package crypto

import java.lang.foreign.*
import java.lang.foreign.ValueLayout.*
import java.lang.invoke.MethodHandle

/** FFM (Panama) binding to libsodium (Constitution I: call a vetted library; no hand-rolled
  * crypto). Exposes ChaCha20-Poly1305 IETF AEAD and Blake2b (`crypto_generichash`). The native
  * library is resolved from `LIBSODIUM_PATH` or common Homebrew/system locations. */
object Sodium:
  val KeyBytes: Int = 32 // crypto_aead_chacha20poly1305_ietf_KEYBYTES
  val NpubBytes: Int = 12 // ..._NPUBBYTES (IETF nonce)
  val ABytes: Int = 16 // ..._ABYTES (Poly1305 tag)

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
