package ping

import crypto.Crypto
import org.scalacheck.Arbitrary.arbitrary
import org.scalacheck.Gen
import org.scalatest.funsuite.AnyFunSuite
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

import notify.Notification

/** Property/example tests for [[ping.DevNotificationServer]]'s sealed-token security invariants
  * (T027, FR-003/FR-004). The server seals one-hot notify tokens with AEAD and aggregates them by
  * bitwise-OR over a shared (round, label). These properties assert that a sender holding one
  * sealed token can flip ONLY its own bit, that forged/tampered/truncated/replayed blobs are
  * rejected, and that aggregation OR-composes and clears correctly.
  *
  * The rejection properties plant a *legitimate* signal (`witnessBit` on `labelA`) first, so a
  * "rejected blob flipped nothing" assertion is non-vacuous: it confirms the bad blob left the
  * digest at exactly that one known bit instead of trivially observing an empty fresh server.
  *
  * Per Constitution II, assertions never depend on secret values leaking through error messages:
  * the only message text checked here ("round mismatch") is a fixed, public string. All forged
  * bytes are drawn from ScalaCheck generators (not an unseeded RNG) so any counterexample is
  * reproducible from the reported seed and shrinks. */
class SealedTokenPropertySpec extends AnyFunSuite with ScalaCheckDrivenPropertyChecks:

  private def server(): DevNotificationServer =
    DevNotificationServer(Array.tabulate(Crypto.KeyBytes)(_.toByte))

  private val labelA = "alice".getBytes
  private val labelB = "bob".getBytes
  private val witnessBit = 1 // a real bit we plant on labelA to detect any corruption of state
  // Poly1305 tag length (crypto_aead_..._ABYTES); a sealed blob is nonce ++ tag ++ ciphertext, so
  // a forgery must be at least this long past the nonce to exercise tag verification (not the
  // too-short "malformed" fast path). Not re-exported on Crypto, so pinned here as a public const.
  private val AeadTagBytes = 16

  // Generators kept in-range: bit positions 0..MaxBits-1, full-range rounds (uint64 round_ids
  // >= 2^63 surface as negative Long), and arbitrary-length labels.
  private val positions: Gen[Int] = Gen.choose(0, Notification.MaxBits - 1)
  private val rounds: Gen[Long] = arbitrary[Long]
  private val labels: Gen[Array[Byte]] = Gen.listOf(arbitrary[Byte]).map(_.toArray)
  private def bytesOfLen(len: Int): Gen[Array[Byte]] =
    Gen.listOfN(len, arbitrary[Byte]).map(_.toArray)

  /** Plant one legitimate signal so the post-rejection digest is a known non-empty witness
    * (`witnessBit` set, popcount 1). A passing rejection then proves the bad blob flipped no bit,
    * rather than passing trivially against an all-zero fresh server. */
  private def withWitness(round: Long): DevNotificationServer =
    val s = server()
    assert(s.signal(round, s.issueToken(round, witnessBit, labelA)).isRight)
    s

  private def assertWitnessIntact(s: DevNotificationServer, round: Long): Unit =
    val d = s.digest(round, labelA)
    assert(
      d.get(witnessBit) && d.popcount == 1
    ) // exactly the planted bit; the bad blob flipped none

  test("a sealed token flips EXACTLY its own bit under its (round,label) and no other (FR-003)"):
    forAll(rounds, positions, labels) { (round, bit, lbl) =>
      val s = server()
      assert(s.signal(round, s.issueToken(round, bit, lbl)).isRight)
      val d = s.digest(round, lbl)
      assert(d.get(bit))
      assert(d.popcount == 1) // exactly one bit, the token's own
    }

  test("distinct bits for one (round,label) all OR together (FR-004)"):
    forAll(rounds, Gen.listOfN(8, positions)) { (round, rawBits) =>
      val bits = rawBits.distinct
      val s = server()
      bits.foreach(b => assert(s.signal(round, s.issueToken(round, b, labelA)).isRight))
      val d = s.digest(round, labelA)
      bits.foreach(b => assert(d.get(b)))
      assert(d.popcount == bits.size)
    }

  test("a forged blob of random bytes is rejected and flips nothing (cannot forge a bit, FR-003)"):
    // Lower bound NonceBytes + AeadABytes so the blob has a full nonce AND tag-length ciphertext:
    // this is a genuine forgery that must fail tag verification, not a too-short malformed blob.
    val minForged = Crypto.NonceBytes + AeadTagBytes
    forAll(Gen.choose(minForged, minForged + 128).flatMap(bytesOfLen)) { forged =>
      val s = withWitness(1L)
      assert(s.signal(1L, forged).isLeft)
      assertWitnessIntact(s, 1L) // forgery flipped no real bit
      assert(s.digest(1L, labelB).isEmpty) // and touched no other label
    }

  test("a tampered sealed blob (single flipped byte) is rejected (AEAD authentication)"):
    forAll(rounds, positions, labels, Gen.choose(0, Int.MaxValue)) { (round, bit, lbl, raw) =>
      val s = server()
      val tok = s.issueToken(round, bit, lbl)
      val idx = raw % tok.length
      tok(idx) = (tok(idx) ^ 0x01).toByte // flip one bit of one byte (nonce or ciphertext)
      assert(s.signal(round, tok).isLeft)
      assert(s.digest(round, lbl).isEmpty) // tamper flipped nothing on a fresh server
    }

  test("a truncated sealed blob is rejected (both the malformed and AEAD paths)"):
    forAll(rounds, positions, labels, Gen.choose(0, Int.MaxValue)) { (round, bit, lbl, raw) =>
      val s = server()
      val tok = s.issueToken(round, bit, lbl)
      val keep = raw % tok.length // 0..len-1, always strictly shorter than the sealed blob
      assert(s.signal(round, tok.take(keep)).isLeft)
      assert(s.digest(round, lbl).isEmpty)
    }

  test("a sender cannot forge another buddy's bit or label by tampering the sealed blob (FR-003)"):
    // A holds a token sealed for (round, bitA, labelA). Tampering ANY byte to try to make it open
    // as a different bit, or retarget labelB, fails AEAD — A can never set bitB nor touch labelB.
    forAll(positions, Gen.choose(0, Int.MaxValue)) { (bitA, raw) =>
      val s = withWitness(7L) // labelA already holds witnessBit
      val tok = s.issueToken(7L, bitA, labelB) // a token A is NOT authorized to use (B's label)
      val idx = raw % tok.length
      tok(idx) = (tok(idx) ^ 0x01).toByte
      assert(s.signal(7L, tok).isLeft) // any mutation is rejected
      assertWitnessIntact(s, 7L) // A's own label unchanged
      assert(s.digest(7L, labelB).isEmpty) // B's label never set by a forged blob
    }

  test("round-binding: a token for round R is rejected when signaled into R' != R"):
    forAll(rounds, rounds, positions, labels) { (r, rOther, bit, lbl) =>
      whenever(r != rOther) {
        val s = server()
        val tok = s.issueToken(r, bit, lbl)
        assert(s.signal(rOther, tok) == Left("round mismatch")) // fixed, public error string
        assert(s.digest(rOther, lbl).isEmpty) // wrong-round signal flips nothing
      }
    }

  test("a round-bound token still applies in its OWN round (round-binding is not over-broad)"):
    forAll(rounds, positions, labels) { (r, bit, lbl) =>
      val s = server()
      assert(s.signal(r, s.issueToken(r, bit, lbl)).isRight)
      assert(s.digest(r, lbl).get(bit))
    }

  test("digestAndReset clears the (round,label) bits; re-read yields an all-zero carrier"):
    forAll(rounds, positions, labels) { (round, bit, lbl) =>
      val s = server()
      assert(s.signal(round, s.issueToken(round, bit, lbl)).isRight)
      val consumed = s.digestAndReset(round, lbl)
      assert(consumed.get(bit) && consumed.popcount == 1)
      assert(s.digestAndReset(round, lbl).isEmpty) // cleared on consume
      assert(s.digest(round, lbl).isEmpty) // carrier afterwards
    }

  test("no mail yields an all-zero carrier digest (uniformity, FR-012)"):
    forAll(rounds, labels) { (round, lbl) =>
      val s = server()
      assert(s.digest(round, lbl).isEmpty)
      assert(s.digestAndReset(round, lbl).isEmpty)
    }
