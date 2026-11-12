package engine

import frame.Frame
import org.scalatest.funsuite.AnyFunSuite

import java.nio.charset.StandardCharsets.UTF_8

/** `DoubleRatchet` re-sealing and the detailed decrypt result (offline-delegation.md §4.1, §4.5).
  * Cross-platform: compiled into both the JVM and the Scala.js build, so the re-seal and duplicate
  * detection hold identically on JCA and `@noble`.
  *
  * The properties:
  *   - `encryptRetained` steps the sending chain exactly once; any number of `reseal`s step nothing;
  *   - re-seals are byte-distinct, the first copy delivers, every later copy is `Consumed` at the
  *     same position, and a `Consumed` result mutates nothing;
  *   - duplicates are recognised through an OLDER stashed epoch, and a frame still ahead in the
  *     current chain is never mistaken for one;
  *   - a tampered body is `Undecryptable`, not `Consumed`;
  *   - a wiped handle is dead and cannot be re-sealed. */
class DoubleRatchetResealCrossSpec extends AnyFunSuite:
  import DoubleRatchet.DecryptResult.*

  private def pair(seed: Byte): (DoubleRatchet, DoubleRatchet) =
    val root = Array.fill[Byte](32)(seed)
    (DoubleRatchet.initInitiator(root), DoubleRatchet.initResponder(root))
  private def inner(msg: String): Array[Byte] =
    Frame.pad(msg.getBytes(UTF_8), DoubleRatchet.InnerSize).toOption.get
  private def text(b: Array[Byte]): String =
    new String(Frame.unpad(b, DoubleRatchet.InnerSize).toOption.get, UTF_8)
  private def hex(b: Array[Byte]): String = b.map(x => f"${x & 0xff}%02x").mkString

  test("re-seals are byte-distinct; the first delivers, every later copy is Consumed"):
    val (alice, bob) = pair(1)
    val (wire, r) = alice.encryptRetained(inner("hello"))
    val copies = Seq.fill(20)(DoubleRatchet.reseal(r))
    val all = (wire +: copies).map(hex)
    assert(all.distinct.size == all.size, "every re-seal must be new bytes")
    val pos = bob.decryptDetailed(copies.head) match
      case Delivered(b, p) => assert(text(b) == "hello"); p
      case other => fail(s"the first copy must deliver: $other")
    for c <- wire +: copies.tail do
      assert(
        bob.decryptDetailed(c) == Consumed(pos),
        "a later copy is a duplicate at the same place"
      )
    // The classic API still reports a duplicate as undecryptable.
    assert(bob.decrypt(copies.last).isEmpty)

  test("re-sealing steps no chain: the next fresh message needs no skip"):
    val (alice, bob) = pair(2)
    val (w0, r) = alice.encryptRetained(inner("m0"))
    for _ <- 0 until 5000 do DoubleRatchet.reseal(r): Unit
    val w1 = alice.encrypt(inner("m1"))
    val p0 = bob.decryptDetailed(w0) match
      case Delivered(_, p) => p
      case other => fail(s"m0 must deliver: $other")
    bob.decryptDetailed(w1) match
      case Delivered(b, p1) =>
        assert(text(b) == "m1")
        assert(p1.dhPub == p0.dhPub && p1.n == p0.n + 1, s"m1 is the very next position: $p0 → $p1")
      case other => fail(s"m1 must deliver right after m0, 5000 re-seals later: $other")

  test("a Consumed duplicate mutates nothing"):
    val (alice, bob) = pair(3)
    val (w0, r) = alice.encryptRetained(inner("m0"))
    assert(bob.decryptDetailed(w0).isInstanceOf[Delivered])
    for _ <- 0 until 50 do
      assert(bob.decryptDetailed(DoubleRatchet.reseal(r)).isInstanceOf[Consumed])
    // Bob's state is unchanged: he can still answer, and alice still reads him.
    val reply = bob.encrypt(inner("reply"))
    assert(alice.decrypt(reply).map(text).contains("reply"))
    assert(bob.decrypt(alice.encrypt(inner("m1"))).map(text).contains("m1"))

  test("a duplicate is recognised through an OLDER stashed epoch while that epoch is live"):
    val (alice, bob) = pair(4)
    val (w0, r0) = alice.encryptRetained(inner("m0"))
    val wKeep = alice.encrypt(inner("m-keep"))
    val w2 = alice.encrypt(inner("m2"))
    // Out of order: m2 first stashes m0's and m-keep's keys under this chain's header key.
    assert(bob.decrypt(w2).map(text).contains("m2"))
    // A DH step on both sides moves bob's receiving chain on, so that stash is now an OLDER epoch.
    assert(alice.decrypt(bob.encrypt(inner("b0"))).map(text).contains("b0"))
    assert(bob.decrypt(alice.encrypt(inner("m3"))).map(text).contains("m3"))
    // m0 still delivers from the stash; while m-keep keeps that epoch alive, a re-seal of m0 is
    // recognised as a duplicate at m0's position.
    val p0 = bob.decryptDetailed(w0) match
      case Delivered(b, p) => assert(text(b) == "m0"); p
      case other => fail(s"m0 must deliver from the stash: $other")
    assert(bob.decryptDetailed(DoubleRatchet.reseal(r0)) == Consumed(p0))
    // Once the epoch drains its header key is wiped (forward secrecy), so a duplicate can no longer
    // be placed: it is Undecryptable. The engine treats that like any undecryptable frame at the
    // pair's token and pays the ack with a re-seal, never a ratchet step.
    assert(bob.decrypt(wKeep).map(text).contains("m-keep"))
    assert(bob.decryptDetailed(DoubleRatchet.reseal(r0)) == Undecryptable)

  test("a frame still AHEAD in the current chain is never mistaken for a duplicate"):
    val (alice, bob) = pair(5)
    val w0 = alice.encrypt(inner("m0"))
    val w1 = alice.encrypt(inner("m1"))
    val w2 = alice.encrypt(inner("m2"))
    assert(bob.decrypt(w0).isDefined)
    assert(bob.decrypt(w2).map(text).contains("m2")) // stashes m1's key in the CURRENT epoch
    bob.decryptDetailed(w1) match
      case Delivered(b, _) => assert(text(b) == "m1")
      case other => fail(s"m1 is out of order, not a duplicate: $other")

  test("a tampered body is Undecryptable, not Consumed, and consumes nothing"):
    val (alice, bob) = pair(6)
    val (w0, _) = alice.encryptRetained(inner("m0"))
    val bad = w0.clone()
    bad(bad.length - 1) = (bad(bad.length - 1) ^ 1).toByte
    assert(bob.decryptDetailed(bad) == Undecryptable)
    assert(bob.decrypt(w0).map(text).contains("m0"), "the genuine frame still delivers")

  test("wipe kills the handle, idempotently, and a wiped handle cannot be re-sealed"):
    val (alice, _) = pair(7)
    val (_, r) = alice.encryptRetained(inner("secret"))
    assert(r.isLive)
    r.wipe()
    assert(!r.isLive)
    r.wipe() // idempotent
    intercept[IllegalArgumentException](DoubleRatchet.reseal(r)): Unit
