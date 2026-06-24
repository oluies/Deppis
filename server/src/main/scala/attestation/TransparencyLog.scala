package attestation

import java.security.MessageDigest

/** RFC 6962-style **append-only Merkle transparency log** over SHA-256 (Constitution X, T057).
  *
  * The metadata-privacy claim trusts the enclave only because a verified attestation appraises its
  * measurement against **transparency-logged reference values** — the published, append-only,
  * publicly-auditable set of code measurements policy accepts. This is that log's cryptographic core:
  * a Merkle tree of reference entries supporting
  *   - **inclusion proofs**: "measurement X is in the log committed to by root R" — so a relying party
  *     accepts a reference value ONLY if it is provably logged (not slipped in out of band), and
  *   - **consistency proofs**: "the size-`n` log with root R₂ is an append-only extension of the
  *     size-`m` log with root R₁" — so the operator cannot rewrite history to retroactively trust
  *     different code.
  *
  * SHA-256 is the JCA primitive (Constitution I — not hand-rolled); the Merkle construction is the
  * standard RFC 6962 algorithm with domain-separated leaf/node hashing (`0x00`/`0x01` prefixes), built
  * over it and carrying the property tests in `TransparencyLogSpec`. What is software here is the LOG
  * (publish + prove); producing a measurement from a **reproducible enclave build** is the
  * toolchain/hardware-gated other half of T057 (see `deploy/enclave/README.md`). */
object TransparencyLog:

  private def sha256(parts: Array[Byte]*): Array[Byte] =
    val md = MessageDigest.getInstance("SHA-256")
    parts.foreach(md.update)
    md.digest()

  /** Leaf hash with RFC 6962 domain separation: `SHA-256(0x00 ‖ entry)`. */
  def leafHash(entry: Array[Byte]): Array[Byte] = sha256(Array(0.toByte), entry)

  /** Interior node hash: `SHA-256(0x01 ‖ left ‖ right)`. */
  def nodeHash(left: Array[Byte], right: Array[Byte]): Array[Byte] =
    sha256(Array(1.toByte), left, right)

  /** The hash of the empty tree (RFC 6962): `SHA-256()`. */
  val emptyRoot: Array[Byte] = sha256()

  private def eq(a: Array[Byte], b: Array[Byte]): Boolean = MessageDigest.isEqual(a, b)

  /** Largest power of two STRICTLY less than `n` (n ≥ 2). */
  private def k(n: Int): Int =
    var p = 1
    while p * 2 < n do p *= 2
    p

  /** Merkle Tree Hash (MTH) of a list of leaf entries — the log root over those entries. */
  def root(entries: Vector[Array[Byte]]): Array[Byte] =
    entries.size match
      case 0 => emptyRoot
      case 1 => leafHash(entries.head)
      case n =>
        val split = k(n)
        nodeHash(root(entries.take(split)), root(entries.drop(split)))

  // ---- Inclusion (RFC 6962 §2.1.1) ------------------------------------------------------------

  /** Prover: the audit path proving `entries(index)` is the `index`-th leaf of `root(entries)`. */
  def inclusionProof(entries: Vector[Array[Byte]], index: Int): Vector[Array[Byte]] =
    require(index >= 0 && index < entries.size, "index out of range")
    def path(m: Int, d: Vector[Array[Byte]]): Vector[Array[Byte]] =
      if d.size == 1 then Vector.empty
      else
        val split = k(d.size)
        if m < split then path(m, d.take(split)) :+ root(d.drop(split))
        else path(m - split, d.drop(split)) :+ root(d.take(split))
    path(index, entries)

  /** Verifier: recompute the root from a leaf hash + audit path WITHOUT the other entries, and check
    * it equals `expectedRoot` (RFC 6962 §2.1.1). The relying party runs exactly this. */
  def verifyInclusion(
      leaf: Array[Byte],
      index: Int,
      treeSize: Int,
      proof: Vector[Array[Byte]],
      expectedRoot: Array[Byte]
  ): Boolean =
    if index < 0 || index >= treeSize then false
    else
      var fn = index
      var sn = treeSize - 1
      var r = leaf
      var i = 0
      var ok = true
      while sn > 0 && ok do
        if i >= proof.size then ok = false
        else
          val p = proof(i); i += 1
          if (fn & 1) == 1 || fn == sn then
            r = nodeHash(p, r)
            if (fn & 1) == 0 then while (fn & 1) == 0 && fn != 0 do { fn >>= 1; sn >>= 1 }
          else r = nodeHash(r, p)
          fn >>= 1; sn >>= 1
      ok && i == proof.size && eq(r, expectedRoot)

  // ---- Consistency (RFC 6962 §2.1.2) ----------------------------------------------------------

  /** Prover: a proof that the size-`m` prefix is consistent with the full size-`n` tree (m ≤ n). */
  def consistencyProof(entries: Vector[Array[Byte]], m: Int): Vector[Array[Byte]] =
    val n = entries.size
    require(m >= 0 && m <= n, "m out of range")
    def subproof(m: Int, d: Vector[Array[Byte]], complete: Boolean): Vector[Array[Byte]] =
      if m == d.size then (if complete then Vector.empty else Vector(root(d)))
      else
        val split = k(d.size)
        if m <= split then subproof(m, d.take(split), complete) :+ root(d.drop(split))
        else subproof(m - split, d.drop(split), false) :+ root(d.take(split))
    if m == 0 || m == n then Vector.empty else subproof(m, entries, true)

  /** Verifier: check a consistency proof relates `oldRoot` (size `m`) to `newRoot` (size `n`) as an
    * append-only extension (RFC 6962 §2.1.2). Reconstructs both roots from the proof alone. */
  def verifyConsistency(
      m: Int,
      n: Int,
      proof: Vector[Array[Byte]],
      oldRoot: Array[Byte],
      newRoot: Array[Byte]
  ): Boolean =
    if m < 0 || m > n then false
    else if m == 0 then proof.isEmpty // an empty prefix is consistent with anything
    else if m == n then proof.isEmpty && eq(oldRoot, newRoot)
    else
      // RFC 6962 §2.1.2 verification.
      val path =
        if (m & (m - 1)) == 0 then oldRoot +: proof
        else proof // prepend MTH(old) if m is a power of 2
      if path.isEmpty then false
      else
        var fn = m - 1
        var sn = n - 1
        while (fn & 1) == 1 do { fn >>= 1; sn >>= 1 }
        var fr = path.head
        var sr = path.head
        var i = 1
        var ok = true
        while sn > 0 && ok do
          if i >= path.size then ok = false
          else
            val c = path(i); i += 1
            if (fn & 1) == 1 || fn == sn then
              fr = nodeHash(c, fr)
              sr = nodeHash(c, sr)
              if (fn & 1) == 0 then while (fn & 1) == 0 && fn != 0 do { fn >>= 1; sn >>= 1 }
            else sr = nodeHash(sr, c)
            fn >>= 1; sn >>= 1
        ok && i == path.size && eq(fr, oldRoot) && eq(sr, newRoot)
