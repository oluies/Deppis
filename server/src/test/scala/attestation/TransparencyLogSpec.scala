package attestation

import org.scalatest.funsuite.AnyFunSuite

/** RFC 6962 Merkle transparency-log proofs (T057). The prover (which holds all entries) and the
  * verifier (which holds only proofs + roots) are exercised against each other for every small tree
  * size and every position — a passing round-trip validates both — plus forgery/tamper rejection, the
  * load-bearing security property: a relying party must accept a reference value ONLY with a real proof. */
class TransparencyLogSpec extends AnyFunSuite:

  import TransparencyLog.*

  private def entry(i: Int): Array[Byte] = s"measurement-$i".getBytes("UTF-8")
  private def log(n: Int): Vector[Array[Byte]] = (0 until n).map(entry).toVector
  private def flip(b: Array[Byte]): Array[Byte] = {
    val c = b.clone(); c(0) = (c(0) ^ 0x01).toByte; c
  }

  test("leaf and node hashing are domain-separated (a leaf can never equal an interior node)"):
    // 0x00 vs 0x01 prefixes (RFC 6962) — without this a second-preimage attack could forge structure.
    assert(
      !java.util.Arrays.equals(leafHash(entry(0)), nodeHash(leafHash(entry(0)), leafHash(entry(1))))
    )

  test("KAT: root of a 2-leaf tree is nodeHash(leaf0, leaf1)"):
    val r = root(log(2))
    assert(java.util.Arrays.equals(r, nodeHash(leafHash(entry(0)), leafHash(entry(1)))))

  test("inclusion: every leaf of every tree (size 1..16) verifies against the root"):
    for n <- 1 to 16 do
      val d = log(n)
      val r = root(d)
      for idx <- 0 until n do
        val proof = inclusionProof(d, idx)
        assert(
          verifyInclusion(leafHash(entry(idx)), idx, n, proof, r),
          s"n=$n idx=$idx must verify"
        )

  test("inclusion: a tampered leaf, proof node, root, or index is REJECTED"):
    val n = 11; val d = log(n); val r = root(d); val idx = 6
    val proof = inclusionProof(d, idx)
    val leaf = leafHash(entry(idx))
    assert(verifyInclusion(leaf, idx, n, proof, r))
    assert(!verifyInclusion(flip(leaf), idx, n, proof, r), "tampered leaf")
    assert(!verifyInclusion(leaf, idx, n, proof, flip(r)), "tampered root")
    assert(
      !verifyInclusion(leaf, idx, n, proof.updated(0, flip(proof(0))), r),
      "tampered proof node"
    )
    assert(!verifyInclusion(leaf, idx + 1, n, proof, r), "wrong index")
    assert(!verifyInclusion(leaf, idx, n, proof.drop(1), r), "truncated proof")

  test("inclusion: a leaf NOT in the log has no proof that verifies (unlogged ⇒ untrusted)"):
    val n = 8; val d = log(n); val r = root(d)
    val rogue = leafHash("never-logged".getBytes("UTF-8"))
    // No index/proof from the genuine log makes the rogue leaf verify.
    assert((0 until n).forall(i => !verifyInclusion(rogue, i, n, inclusionProof(d, i), r)))

  test("consistency: every prefix m of every tree n (1..16) verifies as an append-only extension"):
    for n <- 1 to 16; m <- 0 to n do
      val d = log(n)
      val newRoot = root(d)
      val oldRoot = root(d.take(m))
      val proof = consistencyProof(d, m)
      assert(verifyConsistency(m, n, proof, oldRoot, newRoot), s"m=$m n=$n must be consistent")

  test("consistency: a rewritten history is REJECTED (the append-only guarantee)"):
    val n = 13; val m = 5
    val d = log(n)
    val newRoot = root(d)
    val oldRoot = root(d.take(m))
    val proof = consistencyProof(d, m)
    assert(verifyConsistency(m, n, proof, oldRoot, newRoot))
    // A different "old" root (operator claims the size-m prefix was something else) ⇒ rejected.
    val forgedOld = root(d.take(m).updated(2, entry(99)))
    assert(!verifyConsistency(m, n, proof, forgedOld, newRoot), "forged old root")
    // A different new root ⇒ rejected.
    assert(!verifyConsistency(m, n, proof, oldRoot, flip(newRoot)), "tampered new root")
    // Tampered proof node ⇒ rejected.
    assert(
      !verifyConsistency(m, n, proof.updated(0, flip(proof(0))), oldRoot, newRoot),
      "tampered proof"
    )
