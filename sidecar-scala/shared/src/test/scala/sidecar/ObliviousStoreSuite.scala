package sidecar

import munit.FunSuite

/** Ports `oblivious-sidecar/src/store.rs`'s own unit tests, plus the invariants its gRPC front
  * relies on. A benchmark of an implementation that does not match the original measures nothing,
  * so these exist to pin behavioural parity — NOT to make any privacy claim (see [[ObliviousStore]]).
  *
  * Runs on BOTH the JVM and Scala Native, from this one source. */
class ObliviousStoreSuite extends FunSuite:

  import ObliviousStore.{FrameLen, TokenLen}

  private def tok(b: Int): Array[Byte] = Array.fill(TokenLen)(b.toByte)
  private def frame(b: Int): Array[Byte] = Array.fill(FrameLen)(b.toByte)
  private def out(): Array[Byte] = new Array[Byte](FrameLen)

  test("a written frame reads back exactly once (single-use, FR-014)"):
    val s = new ObliviousStore(16)
    assert(s.write(tok(5), frame(7)))
    val o = out()
    assert(s.readSealed(tok(5), o), "the token must hit")
    assert(o.sameElements(frame(7)))
    assert(!s.readSealed(tok(5), o), "the SAME token must not hit twice")
    assert(o.forall(_ == 0), "a miss must yield carrier zeros")

  test("a miss yields carrier zeros and a false tag, not a short result"):
    val s = new ObliviousStore(8)
    val o = out()
    assert(!s.readSealed(tok(99), o))
    assertEquals(o.length, FrameLen)
    assert(o.forall(_ == 0))

  test("a hit in the LAST slot reads back like a hit in the first"):
    // The Rust test asserts this via its touch counter. Without `#[cfg(test)]`-style instrumentation
    // the observable claim here is that position does not change the RESULT — the full-scan
    // structure is what makes that true, and it is what the benchmark actually exercises.
    val s = new ObliviousStore(16)
    for i <- 0 until 15 do assert(s.write(tok(i + 1), frame(0)))
    assert(s.write(tok(200), frame(9))) // lands in the last slot
    val o = out()
    assert(s.readSealed(tok(200), o))
    assert(o.sameElements(frame(9)))

  test("a consumed slot is zeroized, so the frame cannot be recovered"):
    val s = new ObliviousStore(4)
    assert(s.write(tok(5), frame(7)))
    assert(s.readSealed(tok(5), out()))
    // Every slot is free again, and no residue is readable through any token.
    for b <- 0 until 256 do assert(!s.readSealed(tok(b), out()), s"token $b must not hit")

  test("writes fail closed when the store is full — the only data-independent signal"):
    val s = new ObliviousStore(2)
    assert(s.write(tok(1), frame(1)))
    assert(s.write(tok(2), frame(2)))
    assert(!s.write(tok(3), frame(3)), "a full store must report the failure")
    // and the rejected write must not have displaced anything
    val o = out()
    assert(s.readSealed(tok(1), o) && o.sameElements(frame(1)))

  test("a freed slot is reused, so capacity is a steady-state bound not a lifetime one"):
    val s = new ObliviousStore(1)
    for round <- 0 until 50 do
      assert(s.write(tok(round % 251), frame(round % 251)), s"round $round should find a free slot")
      val o = out()
      assert(s.readSealed(tok(round % 251), o))
      assert(o.sameElements(frame(round % 251)))

  test("tokens differing in a single bit do not collide"):
    val s = new ObliviousStore(8)
    val a = tok(0)
    val b = tok(0); b(TokenLen - 1) = 1
    assert(s.write(a, frame(1)))
    assert(s.write(b, frame(2)))
    val o = out()
    assert(s.readSealed(b, o))
    assert(o.sameElements(frame(2)), "the one-bit-different token must fetch ITS frame")
    assert(s.readSealed(a, o))
    assert(o.sameElements(frame(1)))

  test("a byte with the high bit set survives the round trip (no sign extension)"):
    // The conditional assignments do their arithmetic in Int; a missing `& 0xff` would corrupt any
    // frame byte >= 0x80 while leaving every ASCII-ish test above green.
    val s = new ObliviousStore(4)
    val t = Array.tabulate(TokenLen)(i => (0x80 + i).toByte)
    val f = Array.tabulate(FrameLen)(i => (i & 0xff).toByte)
    assert(s.write(t, f))
    val o = out()
    assert(s.readSealed(t, o))
    assert(o.sameElements(f))
