package crypto

import java.lang.foreign.*
import java.lang.foreign.ValueLayout.*
import java.lang.invoke.MethodHandle

/** FFM (Panama) binding to **liboqs** (Open Quantum Safe) for the NIST post-quantum standards
  * (Constitution I: call a vetted library; NO hand-rolled crypto). Exposes:
  *   - **ML-KEM-768** (FIPS 203) — the key-encapsulation used for the PQ half of the hybrid handshake.
  *   - **ML-DSA-65** (FIPS 204) — the signature used to authenticate PQ material.
  *
  * liboqs ships as a static lib in Homebrew; build a shared lib once with `crypto/build-liboqs.sh`
  * (or point `OQS_PATH` at your own `liboqs.dylib`). Sizes are the standardized parameter-set lengths,
  * so buffers are exact; the wrapper never trusts a length from untrusted input. */
object Oqs:

  // ---- FIPS 203 ML-KEM-768 parameter sizes ----
  object MlKem768:
    val Name = "ML-KEM-768"
    val PublicKeyBytes = 1184
    val SecretKeyBytes = 2400
    val CiphertextBytes = 1088
    val SharedSecretBytes = 32

  // ---- FIPS 204 ML-DSA-65 parameter sizes ----
  object MlDsa65:
    val Name = "ML-DSA-65"
    val PublicKeyBytes = 1952
    val SecretKeyBytes = 4032
    val SignatureMaxBytes = 3309 // ML-DSA-65 signatures are fixed-size, but sign reports the length

  private val linker: Linker = Linker.nativeLinker()
  private val arena: Arena = Arena.ofShared() // process-lifetime: holds the library lookup

  private val lookup: SymbolLookup =
    val candidates = sys.env.get("OQS_PATH").toList ++ List(
      s"${sys.props.getOrElse("user.home", "")}/.deppis-liboqs/liboqs.dylib",
      "/opt/homebrew/opt/liboqs/lib/liboqs.dylib",
      "/opt/homebrew/lib/liboqs.dylib",
      "/usr/local/lib/liboqs.dylib",
      "/usr/local/lib/liboqs.so",
      "/usr/lib/x86_64-linux-gnu/liboqs.so",
      "/usr/lib/liboqs.so"
    )
    candidates.iterator
      .flatMap(p =>
        try Some(SymbolLookup.libraryLookup(p, arena))
        catch case _: Throwable => None
      )
      .nextOption()
      .getOrElse(
        throw new RuntimeException("liboqs not found; run crypto/build-liboqs.sh or set OQS_PATH")
      )

  private def h(name: String, desc: FunctionDescriptor): MethodHandle =
    val sym = lookup.find(name).orElseThrow(() => new RuntimeException(s"missing symbol $name"))
    linker.downcallHandle(sym, desc)

  // liboqs auto-initialises on first use, but OQS_init is safe/idempotent when present.
  private val hInit: Option[MethodHandle] =
    try Some(h("OQS_init", FunctionDescriptor.ofVoid()))
    catch case _: Throwable => None
  hInit.foreach(_.invoke())

  private val hKemNew = h("OQS_KEM_new", FunctionDescriptor.of(ADDRESS, ADDRESS))
  private val hKemKeypair =
    h("OQS_KEM_keypair", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS))
  private val hKemEncaps =
    h("OQS_KEM_encaps", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS, ADDRESS))
  private val hKemDecaps =
    h("OQS_KEM_decaps", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS, ADDRESS))
  private val hKemFree = h("OQS_KEM_free", FunctionDescriptor.ofVoid(ADDRESS))

  private val hSigNew = h("OQS_SIG_new", FunctionDescriptor.of(ADDRESS, ADDRESS))
  private val hSigKeypair =
    h("OQS_SIG_keypair", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS))
  private val hSigSign = h(
    "OQS_SIG_sign",
    // sig*, signature*, signature_len*, message*, message_len, secret_key*
    FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS)
  )
  private val hSigVerify = h(
    "OQS_SIG_verify",
    FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS)
  )
  private val hSigFree = h("OQS_SIG_free", FunctionDescriptor.ofVoid(ADDRESS))
  private val hMemCleanse = h("OQS_MEM_cleanse", FunctionDescriptor.ofVoid(ADDRESS, JAVA_LONG))

  private val OqsSuccess = 0

  /** Zero a secret-bearing native segment before its arena is freed. `Arena.close()` releases the
    * memory but does NOT clear it, so a freed page would otherwise retain private-key / shared-secret
    * bytes until reused (Constitution: erase evolved/secret key material). Uses liboqs' own
    * constant-time `OQS_MEM_cleanse` (which the compiler can't optimise away). NOTE: the heap arrays
    * this module RETURNS are the caller's to manage — a copying GC can leave copies of those. */
  private def cleanse(s: MemorySegment, n: Int): Unit = hMemCleanse.invoke(s, n.toLong)

  private def cstr(a: Arena, s: String): MemorySegment = a.allocateFrom(s)
  private def seg(a: Arena, n: Int): MemorySegment = a.allocate(n.toLong)
  private def put(a: Arena, bytes: Array[Byte]): MemorySegment =
    val s = a.allocate(math.max(bytes.length, 1).toLong)
    if bytes.nonEmpty then MemorySegment.copy(bytes, 0, s, JAVA_BYTE, 0L, bytes.length)
    s
  private def get(s: MemorySegment, n: Int): Array[Byte] =
    val out = new Array[Byte](n)
    MemorySegment.copy(s, JAVA_BYTE, 0L, out, 0, n)
    out

  // ---- ML-KEM-768 ----

  final case class KemKeyPair(publicKey: Array[Byte], secretKey: Array[Byte])

  private def withKem[T](body: (Arena, MemorySegment) => T): T =
    val a = Arena.ofConfined()
    try
      val kem = hKemNew.invoke(cstr(a, MlKem768.Name)).asInstanceOf[MemorySegment]
      if kem == MemorySegment.NULL then throw new RuntimeException("OQS_KEM_new returned NULL")
      try body(a, kem)
      finally hKemFree.invoke(kem)
    finally a.close()

  def kemKeypair(): KemKeyPair = withKem { (a, kem) =>
    val pk = seg(a, MlKem768.PublicKeyBytes)
    val sk = seg(a, MlKem768.SecretKeyBytes)
    // `finally` so the native secret key is zeroed even if keypair fails (Arena.close frees, not clears)
    try
      val rc = hKemKeypair.invoke(kem, pk, sk).asInstanceOf[Int]
      if rc != OqsSuccess then throw new RuntimeException(s"OQS_KEM_keypair rc=$rc")
      KemKeyPair(get(pk, MlKem768.PublicKeyBytes), get(sk, MlKem768.SecretKeyBytes))
    finally cleanse(sk, MlKem768.SecretKeyBytes)
  }

  final case class Encapsulation(ciphertext: Array[Byte], sharedSecret: Array[Byte])

  def kemEncaps(publicKey: Array[Byte]): Encapsulation =
    require(publicKey.length == MlKem768.PublicKeyBytes, "ML-KEM-768 public key size")
    withKem { (a, kem) =>
      val ct = seg(a, MlKem768.CiphertextBytes)
      val ss = seg(a, MlKem768.SharedSecretBytes)
      try
        val rc = hKemEncaps.invoke(kem, ct, ss, put(a, publicKey)).asInstanceOf[Int]
        if rc != OqsSuccess then throw new RuntimeException(s"OQS_KEM_encaps rc=$rc")
        Encapsulation(get(ct, MlKem768.CiphertextBytes), get(ss, MlKem768.SharedSecretBytes))
      finally cleanse(ss, MlKem768.SharedSecretBytes) // the shared secret is secret material
    }

  def kemDecaps(ciphertext: Array[Byte], secretKey: Array[Byte]): Array[Byte] =
    require(ciphertext.length == MlKem768.CiphertextBytes, "ML-KEM-768 ciphertext size")
    require(secretKey.length == MlKem768.SecretKeyBytes, "ML-KEM-768 secret key size")
    withKem { (a, kem) =>
      val ss = seg(a, MlKem768.SharedSecretBytes)
      val skSeg = put(a, secretKey)
      try
        val rc = hKemDecaps.invoke(kem, ss, put(a, ciphertext), skSeg).asInstanceOf[Int]
        if rc != OqsSuccess then throw new RuntimeException(s"OQS_KEM_decaps rc=$rc")
        get(ss, MlKem768.SharedSecretBytes)
      finally { cleanse(ss, MlKem768.SharedSecretBytes); cleanse(skSeg, secretKey.length) }
    }

  // ---- ML-DSA-65 ----

  final case class SigKeyPair(publicKey: Array[Byte], secretKey: Array[Byte])

  private def withSig[T](body: (Arena, MemorySegment) => T): T =
    val a = Arena.ofConfined()
    try
      val sig = hSigNew.invoke(cstr(a, MlDsa65.Name)).asInstanceOf[MemorySegment]
      if sig == MemorySegment.NULL then throw new RuntimeException("OQS_SIG_new returned NULL")
      try body(a, sig)
      finally hSigFree.invoke(sig)
    finally a.close()

  def sigKeypair(): SigKeyPair = withSig { (a, sig) =>
    val pk = seg(a, MlDsa65.PublicKeyBytes)
    val sk = seg(a, MlDsa65.SecretKeyBytes)
    try
      val rc = hSigKeypair.invoke(sig, pk, sk).asInstanceOf[Int]
      if rc != OqsSuccess then throw new RuntimeException(s"OQS_SIG_keypair rc=$rc")
      SigKeyPair(get(pk, MlDsa65.PublicKeyBytes), get(sk, MlDsa65.SecretKeyBytes))
    finally cleanse(sk, MlDsa65.SecretKeyBytes) // zero the native signing key regardless of outcome
  }

  def sign(message: Array[Byte], secretKey: Array[Byte]): Array[Byte] =
    require(secretKey.length == MlDsa65.SecretKeyBytes, "ML-DSA-65 secret key size")
    withSig { (a, sig) =>
      val out = seg(a, MlDsa65.SignatureMaxBytes)
      val lenP = a.allocate(JAVA_LONG)
      lenP.set(JAVA_LONG, 0L, MlDsa65.SignatureMaxBytes.toLong)
      val msg = put(a, message)
      val skSeg = put(a, secretKey)
      try
        val rc = hSigSign
          .invoke(sig, out, lenP, msg, message.length.toLong, skSeg)
          .asInstanceOf[Int]
        if rc != OqsSuccess then throw new RuntimeException(s"OQS_SIG_sign rc=$rc")
        get(out, lenP.get(JAVA_LONG, 0L).toInt)
      finally
        cleanse(skSeg, secretKey.length) // zero the native signing-key copy regardless of outcome
    }

  /** Verify — returns `true` only on `OQS_SUCCESS`; any other status (bad signature, wrong key) is
    * `false`, with no exception and no branch on secret data (Constitution II). */
  def verify(message: Array[Byte], signature: Array[Byte], publicKey: Array[Byte]): Boolean =
    if publicKey.length != MlDsa65.PublicKeyBytes then false
    else
      withSig { (a, sig) =>
        val rc = hSigVerify
          .invoke(
            sig,
            put(a, message),
            message.length.toLong,
            put(a, signature),
            signature.length.toLong,
            put(a, publicKey)
          )
          .asInstanceOf[Int]
        rc == OqsSuccess
      }
