package engine

import org.scalatest.funsuite.AnyFunSuite

/** The RATCHET-level properties of the continuous-PQ epoch fold — Phase 3 of
  * `design/continuous-pq-ratchet.md` (§4 KDF integration, §7 Phase 3). Cross-platform (JVM +
  * Scala.js) because the fold now sits on the live content ratchet, whose byte-for-byte agreement
  * across platforms is what lets a JS client talk to a JVM one.
  *
  * These tests drive `DoubleRatchet` directly, WITHOUT the engine's transport, so they isolate the
  * one property the whole design exists for: that the folded root genuinely depends on the hybrid-KEM
  * epoch secret. The proof is oracle-free — no test hook exposes the root (a root oracle in
  * production code would be a liability, and `Engine` must never return key material). Instead we use
  * INTEROPERABILITY as the observable: two ratchets agree iff their roots agree, so
  *
  *   - fold BOTH sides with the same `ss`  ⇒ they still talk  (the fold is consistent), and
  *   - fold them with DIFFERENT `ss`       ⇒ they stop talking (the root depends on `ss`), and
  *   - fold only ONE side                  ⇒ they stop talking (the fold is load-bearing —
  *                                            this is the no-fold control the brief asks for).
  *
  * The last two are what make the first non-vacuous: if the epoch secret did not reach the root,
  * both controls would keep decrypting.
  *
  * HONEST SCOPE (Constitution IV): a passing suite here is NOT a PQ claim. It shows the fold is
  * wired and load-bearing; whether it buys `pq_post_compromise_security` is the Phase 5 formal
  * analysis's question, under an attacker model none of these tests represent. */
class EpochFoldCrossSpec extends AnyFunSuite:

  private def root(seed: Byte): Array[Byte] = Array.fill[Byte](32)(seed)
  private def ss(seed: Byte): Array[Byte] = Array.fill[Byte](EpochKdf.KeyBytes)(seed)
  private def inner(tag: Byte): Array[Byte] = Array.fill[Byte](DoubleRatchet.InnerSize)(tag)

  /** A live pair, warmed until BOTH sides can send (the responder needs the initiator's first
    * frame). Returns `(initiator, responder)`. */
  private def warmPair(seed: Byte = 1): (DoubleRatchet, DoubleRatchet) =
    val a = DoubleRatchet.initInitiator(root(seed))
    val b = DoubleRatchet.initResponder(root(seed))
    assert(b.decrypt(a.encrypt(inner(9))).isDefined, "warm-up: responder must open the first frame")
    assert(a.decrypt(b.encrypt(inner(8))).isDefined, "warm-up: initiator must open the reply")
    (a, b)

  private def talks(from: DoubleRatchet, to: DoubleRatchet, tag: Byte): Boolean =
    to.decrypt(from.encrypt(inner(tag))).exists(_.sameElements(inner(tag)))

  /** A full ping-pong — the honest unit of "are these two still in sync".
    *
    * A single hop is NOT: the first frame sent after a fold always decrypts, because the sender's
    * chain key was derived by the very `kdfRk` that PRODUCED the anchor root (from `prk` over the
    * root BEFORE it), so it predates the fold entirely. The fold only feeds the NEXT `kdfRk`, i.e.
    * the receiver's DH step — so a mismatched fold first bites on the REPLY. Judging agreement on
    * one frame would let every divergence test below pass vacuously. */
  private def roundTrip(a: DoubleRatchet, b: DoubleRatchet, tag: Byte): Boolean =
    talks(a, b, tag) && talks(b, a, (tag + 1).toByte)

  // ------------------------------------------------------------------ the shared root chain

  test("both peers traverse ONE shared root chain, at offset positions (the fold's anchor)"):
    // The whole anchoring design rests on this: the peers are NEVER on the same root index at the
    // same time (so "fold your current root" is not a shared instruction), but each side's index is
    // exactly the other's ± 1, and after processing a frame from a chain the receiver sits exactly
    // one index past the sender. That is what makes `committer's rootIndex + 1` a shared anchor.
    val a = DoubleRatchet.initInitiator(root(3))
    val b = DoubleRatchet.initResponder(root(3))
    assert(a.rootIndex == 1, "the initiator's bootstrap already ran one kdfRk")
    assert(b.rootIndex == 0, "the responder holds rk0 itself")
    b.decrypt(a.encrypt(inner(1))): Unit
    assert(b.rootIndex == a.rootIndex + 1, "receiver lands one index past the sender")
    a.decrypt(b.encrypt(inner(2))): Unit
    assert(a.rootIndex == b.rootIndex + 1, "and the lead alternates")
    // Sending never advances the root — only a DH step (a new peer ratchet key) does.
    val before = a.rootIndex
    a.encrypt(inner(3)): Unit
    a.encrypt(inner(4)): Unit
    assert(a.rootIndex == before, "sending must not advance the root chain")

  // ------------------------------------------------ the fold is real, consistent, and load-bearing

  test("a fold at the SAME anchor with the SAME secret keeps both sides interoperable"):
    val (a, b) = warmPair()
    // `b` is the committer: it arms its own NEXT index; `a` is one index ahead already, so `a` folds
    // that same index NOW. This is exactly the engine's EPOCH_COMMIT anchoring, hand-driven.
    val anchor = b.rootIndex + 1
    assert(a.rootIndex == anchor, "the peer of the committer sits on the anchor")
    assert(a.armEpochFold(anchor, ss(0x5a)), "the receiver folds at its live root")
    assert(b.armEpochFold(anchor, ss(0x5a)), "the committer defers to its next root")
    assert(a.epochFoldsApplied == 1, "the receiver's fold committed immediately")
    assert(b.epochFoldsApplied == 0, "the committer's fold is armed, not yet applied")
    assert(b.epochFoldArmed)
    // The committer reaches the anchor on its next DH step and folds there.
    assert(talks(a, b, 0x11), "messages after the fold still decrypt")
    assert(b.epochFoldsApplied == 1, "the committer applied the fold on reaching the anchor")
    assert(!b.epochFoldArmed)
    assert(talks(b, a, 0x12), "and in the other direction")
    assert(talks(a, b, 0x13))

  test(
    "THE property: the post-fold root depends on the KEM secret (differs from a no-fold control)"
  ):
    // Control 1 — NO fold at all: the pair keeps talking. This is the baseline the fold must differ
    // from; without it, "they diverged" below would prove nothing.
    val (c0, d0) = warmPair()
    assert(roundTrip(c0, d0, 0x21), "an un-folded pair talks (control)")

    // Control 2 — the fold is LOAD-BEARING: fold one side only and the chains part company. If the
    // epoch secret never reached the root, this pair would still talk.
    val (c1, d1) = warmPair()
    assert(c1.armEpochFold(c1.rootIndex, ss(0x5a)))
    assert(!roundTrip(c1, d1, 0x23), "a one-sided fold MUST diverge — the root moved")

    // The property itself — the root depends on the SECRET, not merely on "a fold happened": same
    // anchor on both sides, different `ss`, and they diverge.
    val (c2, d2) = warmPair()
    val anchor = d2.rootIndex + 1
    assert(c2.armEpochFold(anchor, ss(0x5a)))
    assert(d2.armEpochFold(anchor, ss(0x5b))) // one byte of the epoch secret differs
    assert(!roundTrip(c2, d2, 0x25), "different epoch secrets MUST yield different roots")

    // …and the same secret at the same anchor does NOT diverge (already covered above, restated here
    // so the three controls sit side by side and the discriminating variable is unambiguous).
    val (c3, d3) = warmPair()
    val anchor3 = d3.rootIndex + 1
    assert(c3.armEpochFold(anchor3, ss(0x5a)))
    assert(d3.armEpochFold(anchor3, ss(0x5a)))
    assert(roundTrip(c3, d3, 0x27), "same secret, same anchor ⇒ same root ⇒ still talking")

  test("a fold at a DIFFERENT anchor diverges — the anchor is load-bearing too"):
    val (a, b) = warmPair()
    val anchor = b.rootIndex + 1
    assert(a.armEpochFold(anchor, ss(0x77)))
    assert(b.armEpochFold(anchor + 2, ss(0x77)), "same secret, anchor two steps later")
    assert(!roundTrip(a, b, 0x31), "same secret at different chain positions still diverges")

  // ----------------------------------------------------------------------- atomicity / fail closed

  test("fail closed: arming at an anchor the chain has PASSED refuses and mutates nothing"):
    val (a, b) = warmPair()
    val stale = a.rootIndex - 1
    assert(!a.armEpochFold(stale, ss(0x42)), "an un-appliable fold must be refused")
    assert(a.epochFoldsApplied == 0)
    assert(!a.epochFoldArmed)
    // The refusal left the ratchet fully usable at the PRE-REKEY epoch — no half-committed state.
    assert(talks(a, b, 0x41) && talks(b, a, 0x42), "a refused fold leaves the pair working")

  test("fail closed: a second arm while one is pending is refused (no silent overwrite)"):
    val (a, b) = warmPair()
    val anchor = a.rootIndex + 2
    assert(a.armEpochFold(anchor, ss(1)))
    assert(!a.armEpochFold(anchor, ss(2)), "an armed fold must not be replaceable")
    assert(a.epochFoldArmed)

  test("disarm releases an armed fold and leaves the pre-rekey epoch intact and usable"):
    val (a, b) = warmPair()
    assert(a.armEpochFold(a.rootIndex + 2, ss(0x33)))
    a.disarmEpochFold()
    assert(!a.epochFoldArmed)
    assert(a.epochFoldsApplied == 0)
    // Both sides never folded, so the pair is untouched — the design §8.2 "Aborted → pre-rekey
    // epoch" transition at the ratchet layer.
    assert(talks(a, b, 0x51) && talks(b, a, 0x52))
    a.disarmEpochFold() // idempotent

  test("a COMMITTED fold is never stripped by a later disarm or a refused arm (§8.2)"):
    val (a, b) = warmPair()
    val anchor = b.rootIndex + 1
    assert(a.armEpochFold(anchor, ss(0x5a)))
    assert(b.armEpochFold(anchor, ss(0x5a)))
    assert(talks(a, b, 0x61), "the pair is folded and healthy")
    assert(a.epochFoldsApplied == 1)
    assert(b.epochFoldsApplied == 1)
    // A subsequent aborted attempt: a refused arm + a disarm must not undo the hardening above.
    assert(!a.armEpochFold(a.rootIndex - 1, ss(0x99.toByte)))
    a.disarmEpochFold()
    b.disarmEpochFold()
    assert(a.epochFoldsApplied == 1, "the prior fold still stands")
    assert(talks(a, b, 0x62) && talks(b, a, 0x63), "and the folded pair still interoperates")

  test("folds compose across epochs: two folds in a row keep both sides in step"):
    val (a, b) = warmPair()
    for (secret, i) <- Seq[Byte](0x11, 0x22, 0x33).zipWithIndex do
      val anchor = b.rootIndex + 1
      assert(a.armEpochFold(anchor, ss(secret)))
      assert(b.armEpochFold(anchor, ss(secret)))
      assert(talks(a, b, (0x70 + i).toByte), s"epoch $i: forward")
      assert(talks(b, a, (0x80 + i).toByte), s"epoch $i: reverse")
    assert(a.epochFoldsApplied == 3)
    assert(b.epochFoldsApplied == 3)

  test("wipe: arming copies the epoch secret, and the caller's wipe cannot blank an armed fold"):
    // §4.4's lifecycle depends on the ratchet owning its own copy: the engine wipes `ss` the moment
    // it arms, so a fold that only referenced the caller's array would fold in zeroes.
    val (a, b) = warmPair()
    val anchor = b.rootIndex + 1
    val secretA = ss(0x5a)
    val secretB = ss(0x5a)
    assert(a.armEpochFold(anchor, secretA))
    assert(b.armEpochFold(anchor, secretB))
    java.util.Arrays.fill(secretA, 0.toByte) // the caller wipes ITS copy, as the engine does
    java.util.Arrays.fill(secretB, 0.toByte)
    assert(roundTrip(a, b, 0x71), "the armed fold survived the caller's wipe")
    assert(b.epochFoldsApplied == 1)
    // …and folding in an all-zero secret is NOT what happened: a pair folded with the zero secret
    // would be a different (still self-consistent) pair, so compare against one built that way.
    val (z, y) = warmPair()
    val zAnchor = y.rootIndex + 1
    assert(z.armEpochFold(zAnchor, Array.fill[Byte](EpochKdf.KeyBytes)(0)))
    assert(y.armEpochFold(zAnchor, ss(0x5a)))
    assert(
      !roundTrip(z, y, 0x73),
      "zero-secret vs real-secret folds diverge (no wiped secret leaked in)"
    )

  test("a fold applies to a root index the peer only passes through mid-DH-step"):
    // The committer folds at an index it reaches INSIDE `dhRatchet` (between the receiving-chain and
    // sending-chain derivations), while the receiver folds it as a persistent root. Both must fold
    // the same value, or a long-idle pair would diverge on the next step. This drives several steps
    // after the fold to exercise the mid-step path repeatedly.
    val (a, b) = warmPair()
    val anchor = b.rootIndex + 1
    assert(a.armEpochFold(anchor, ss(0x5a)))
    assert(b.armEpochFold(anchor, ss(0x5a)))
    for i <- 0 until 6 do
      assert(talks(a, b, (0xa0 + i).toByte), s"ping $i")
      assert(talks(b, a, (0xb0 + i).toByte), s"pong $i")
    assert(a.epochFoldsApplied == 1)
    assert(b.epochFoldsApplied == 1)
