package engine

import frame.Frame
import org.scalatest.funsuite.AnyFunSuite

import java.nio.charset.StandardCharsets.UTF_8

/** Property tests for the DH double ratchet with header encryption (dh-ratchet.md §10). These run on
  * BOTH the JVM (JCA primitives) and Node (`@noble`) — the shared `protocolCore/test` runs the JVM
  * side; the JS mirror (`engine.DoubleRatchetJsSpec`) runs the SAME assertions under Node, pinning the
  * cross-platform parity the ratchet depends on. */
class DoubleRatchetSpec extends AnyFunSuite:

  /** A shared content root, as the handshake would produce (32 bytes). */
  private def contentRoot(seed: Byte): Array[Byte] = Array.fill(32)(seed)

  /** Pair of ratchets bootstrapped from the SAME content root (the symmetric pairing). */
  private def pair(seed: Byte = 7): (DoubleRatchet, DoubleRatchet) =
    (DoubleRatchet.initInitiator(contentRoot(seed)), DoubleRatchet.initResponder(contentRoot(seed)))

  private def inner(msg: String): Array[Byte] =
    Frame.pad(msg.getBytes(UTF_8), DoubleRatchet.InnerSize).toOption.get

  private def text(inner: Array[Byte]): String =
    new String(Frame.unpad(inner, DoubleRatchet.InnerSize).toOption.get, UTF_8)

  test("initiator → responder: bootstrap establishes a working session on the first message"):
    val (alice, bob) = pair()
    assert(alice.canSend, "initiator can send immediately")
    assert(!bob.canSend, "responder cannot send before it has received (initiator-sends-first)")
    val wire = alice.encrypt(inner("hello bob"))
    assert(wire.length == DoubleRatchet.WireSize)
    assert(bob.decrypt(wire).map(text).contains("hello bob"))
    assert(bob.canSend, "responder can send once its receiving DH step established a sending chain")

  test("ordered stream in one direction decrypts in order"):
    val (alice, bob) = pair()
    val msgs = (0 until 5).map(i => s"msg-$i")
    val wires = msgs.map(m => alice.encrypt(inner(m)))
    val got = wires.map(w => bob.decrypt(w).map(text))
    assert(got == msgs.map(Some(_)))

  test("bidirectional ping-pong heals: each receive mixes a FRESH random DH key (PCS mechanism)"):
    val (alice, bob) = pair()
    // m1: A→B (B does its first DH step, generating a fresh sending key)
    assert(bob.decrypt(alice.encrypt(inner("a1"))).map(text).contains("a1"))
    val bobPub1 = bob.sendingPublicKey
    // r1: B→A (A DH-steps, fresh key)
    assert(alice.decrypt(bob.encrypt(inner("b1"))).map(text).contains("b1"))
    val alicePub1 = alice.sendingPublicKey
    // m2: A→B (B DH-steps AGAIN → a NEW fresh sending key, different from bobPub1)
    assert(bob.decrypt(alice.encrypt(inner("a2"))).map(text).contains("a2"))
    val bobPub2 = bob.sendingPublicKey
    // r2: A DH-steps again
    assert(alice.decrypt(bob.encrypt(inner("b2"))).map(text).contains("b2"))
    val alicePub2 = alice.sendingPublicKey
    // Healing = each DH ratchet step injects fresh randomness: the ratchet public key changes every
    // step, so a compromise at one step is recovered after the next uncompromised one.
    assert(!bobPub1.sameElements(bobPub2), "Bob's ratchet key must change across DH steps")
    assert(!alicePub1.sameElements(alicePub2), "Alice's ratchet key must change across DH steps")

  test("sustained ping-pong over many rounds stays in lockstep"):
    val (alice, bob) = pair()
    var ok = true
    (0 until 20).foreach: i =>
      ok &&= bob.decrypt(alice.encrypt(inner(s"a$i"))).map(text).contains(s"a$i")
      ok &&= alice.decrypt(bob.encrypt(inner(s"b$i"))).map(text).contains(s"b$i")
    assert(ok, "every message in a 20-round ping-pong decrypts")

  test("out-of-order delivery within a chain is recovered via skipped keys"):
    val (alice, bob) = pair()
    val w0 = alice.encrypt(inner("m0"))
    val w1 = alice.encrypt(inner("m1"))
    val w2 = alice.encrypt(inner("m2"))
    // Deliver 0, then 2 (skips+stashes 1), then 1 (from the stash).
    assert(bob.decrypt(w0).map(text).contains("m0"))
    assert(bob.decrypt(w2).map(text).contains("m2"))
    assert(bob.decrypt(w1).map(text).contains("m1"))

  test("a missed message across a DH step is recovered (skip on the previous chain)"):
    val (alice, bob) = pair()
    // Alice's first chain: m0, m1 — Bob only sees m0 now, m1 is delayed.
    val a0 = alice.encrypt(inner("a0"))
    val a1 = alice.encrypt(inner("a1"))
    assert(bob.decrypt(a0).map(text).contains("a0"))
    // Bob replies, Alice receives (ping-pong) — both DH-step.
    assert(alice.decrypt(bob.encrypt(inner("b0"))).map(text).contains("b0"))
    // Alice sends on her NEW chain; its header carries PN=2 (her previous chain had 2 messages).
    val a2 = alice.encrypt(inner("a2"))
    // Bob receives a2 first: the DH step stashes the previous chain's missed key (a1's), then a1
    // arrives late and is recovered from the stash.
    assert(bob.decrypt(a2).map(text).contains("a2"))
    assert(bob.decrypt(a1).map(text).contains("a1"))

  test("header encryption removes the linking tag: sealed headers differ across a chain"):
    val (alice, bob) = pair()
    // Bob must receive once so the comparison uses an established session; then Alice sends 3 in a row.
    assert(bob.decrypt(alice.encrypt(inner("x"))).map(text).contains("x"))
    assert(alice.decrypt(bob.encrypt(inner("y"))).map(text).contains("y"))
    val h = (0 until 3).map { i =>
      val w = alice.encrypt(inner(s"same-chain-$i"))
      // The 56-byte sealed-header region (after the 12-byte nonce).
      w.slice(12, 12 + 56).toVector
    }
    // Same underlying ratchet public key across the chain, but the sealed headers are all distinct —
    // the store sees no constant tag to cluster a conversation by (unlinkability, dh-ratchet.md §2).
    assert(h.distinct.size == 3, "sealed headers within one chain must all differ")

  test("a jump beyond MaxSkip is rejected as a carrier without corrupting state"):
    val (alice, bob) = pair()
    assert(bob.decrypt(alice.encrypt(inner("first"))).map(text).contains("first")) // Bob.nr = 1
    // The immediate in-order successor (n=1), captured but not yet delivered.
    val wireNext = alice.encrypt(inner("next"))
    // Alice then races > MaxSkip frames further ahead on the SAME chain; Bob never sees the middle.
    var wireFar: Array[Byte] = null
    (0 to DoubleRatchet.MaxSkip + 1).foreach { i =>
      val w = alice.encrypt(inner(s"far-$i"))
      if i == DoubleRatchet.MaxSkip + 1 then wireFar = w
    }
    // The far frame demands skipping > MaxSkip keys in the current chain ⇒ rejected, no mutation.
    assert(bob.decrypt(wireFar).isEmpty, "an over-MaxSkip jump is dropped like a carrier")
    // Bob is unharmed: the in-order successor still decrypts (his receive counter was not advanced).
    assert(bob.decrypt(wireNext).map(text).contains("next"))

  test("a skip of exactly MaxSkip is accepted (boundary)"):
    val (alice, bob) = pair()
    assert(bob.decrypt(alice.encrypt(inner("base"))).map(text).contains("base")) // Bob.nr = 1
    var wireBound: Array[Byte] = null
    // Produce frames so one sits exactly MaxSkip ahead of Bob's current receive position (nr = 1):
    // its header n = 1 + MaxSkip, so the skip is exactly MaxSkip.
    (0 to DoubleRatchet.MaxSkip).foreach { i =>
      val w = alice.encrypt(inner(s"s-$i")) // i-th frame carries header n = 1 + i
      if i == DoubleRatchet.MaxSkip then wireBound = w
    }
    assert(bob.decrypt(wireBound).map(text).contains(s"s-${DoubleRatchet.MaxSkip}"))

  test("a carrier / garbage frame returns None and leaves the ratchet intact"):
    val (alice, bob) = pair()
    assert(bob.decrypt(alice.encrypt(inner("real"))).map(text).contains("real"))
    val garbage = Array.fill[Byte](DoubleRatchet.WireSize)(0x5a.toByte)
    assert(bob.decrypt(garbage).isEmpty, "garbage matches no header key ⇒ None")
    val tooShort = new Array[Byte](10)
    assert(bob.decrypt(tooShort).isEmpty, "a malformed-length frame ⇒ None")
    // State intact: the next genuine frame still decrypts.
    assert(bob.decrypt(alice.encrypt(inner("after"))).map(text).contains("after"))

  test("a frame for a different pairing does not decrypt"):
    val (alice, _) = pair(seed = 1)
    val (_, eve) = pair(seed = 2) // a responder bootstrapped from a DIFFERENT content root
    assert(eve.decrypt(alice.encrypt(inner("not for you"))).isEmpty)

  test("a valid header with a tampered body leaves the ratchet intact (atomic receive)"):
    val (alice, bob) = pair()
    val w = alice.encrypt(inner("intact?"))
    // Flip a byte in the message region (offset ≥ 68) — the sealed HEADER still authenticates, but the
    // message AEAD will fail. The ratchet must NOT advance (no DH step / skip / counter / key wipe),
    // so the genuine frame for the same position still decrypts afterwards.
    val bad = w.clone()
    bad(DoubleRatchet.WireSize - 1) = (bad(DoubleRatchet.WireSize - 1) ^ 0x01).toByte
    assert(bob.decrypt(bad).isEmpty, "a tampered body ⇒ None")
    assert(
      bob.decrypt(w).map(text).contains("intact?"),
      "the genuine frame still decrypts (state intact)"
    )

  test("replaying a consumed frame returns None (the message key is gone)"):
    val (alice, bob) = pair()
    val w = alice.encrypt(inner("once"))
    assert(bob.decrypt(w).map(text).contains("once"))
    assert(bob.decrypt(w).isEmpty, "the spent message key was wiped ⇒ no second decryption")
