package ping

import crypto.Crypto
import privacy.Privacy
import org.scalatest.funsuite.AnyFunSuite

class DevNotificationServerSpec extends AnyFunSuite:

  private def server(): DevNotificationServer =
    DevNotificationServer(Array.tabulate(Crypto.KeyBytes)(_.toByte))

  private val labelA = "alice".getBytes
  private val labelB = "bob".getBytes
  private val R = 1L

  test("dev notification server is labeled and never metadata-private (Constitution IV)"):
    val s = server()
    assert(!s.metadataPrivate)
    assert(s.label == Privacy.DevLabel)

  test("a sealed token flips exactly its own bit; digest reveals presence not identity"):
    val s = server()
    val tok = s.issueToken(R, 5, labelA)
    assert(s.signal(R, tok).isRight)
    val d = s.digest(R, labelA)
    assert(d.get(5) && d.popcount == 1)

  test("two buddies under one (round,label) OR into a 2-bit digest (FR-004)"):
    val s = server()
    assert(s.signal(R, s.issueToken(R, 3, labelA)).isRight)
    assert(s.signal(R, s.issueToken(R, 9, labelA)).isRight)
    val d = s.digest(R, labelA)
    assert(d.get(3) && d.get(9) && d.popcount == 2)

  test("no waiting mail yields an all-zero carrier digest (uniformity, FR-012)"):
    assert(server().digest(R, labelA).isEmpty)

  test("labels isolate clients: a signal for A does not appear in B's digest"):
    val s = server()
    assert(s.signal(R, s.issueToken(R, 7, labelA)).isRight)
    assert(s.digest(R, labelB).isEmpty)

  test("rounds isolate signals: a signal in round 1 does not appear in round 2"):
    val s = server()
    assert(s.signal(1L, s.issueToken(1L, 4, labelA)).isRight)
    assert(s.digest(2L, labelA).isEmpty) // different round, nothing
    assert(s.digest(1L, labelA).get(4)) // original round still has it

  test("a high-bit (uint64) round binds correctly (-1L == u64::MAX)"):
    val s = server()
    assert(
      s.signal(-1L, s.issueToken(-1L, 5, labelA)).isRight
    ) // accepted in its own (high-bit) round
    assert(s.digest(-1L, labelA).get(5))
    assert(s.signal(2L, s.issueToken(-1L, 5, labelA)).isLeft) // bound to -1L, rejected at round 2

  test("a token bound to one round cannot be replayed into another (round binding)"):
    val s = server()
    val tok = s.issueToken(1L, 4, labelA) // bound to round 1
    assert(s.signal(2L, tok).isLeft) // replay to round 2 rejected
    assert(s.digest(2L, labelA).isEmpty)
    assert(s.signal(1L, tok).isRight) // valid in its own round
    assert(s.digest(1L, labelA).get(4))

  test("digestAndReset consumes only its own (round,label)"):
    val s = server()
    assert(s.signal(1L, s.issueToken(1L, 4, labelA)).isRight)
    assert(s.signal(2L, s.issueToken(2L, 6, labelA)).isRight)
    assert(s.digestAndReset(1L, labelA).get(4)) // consume round 1
    assert(s.digestAndReset(1L, labelA).isEmpty) // cleared
    assert(s.digestAndReset(2L, labelA).get(6)) // round 2 untouched

  test("stale rounds are evicted by the retention window (bounded growth)"):
    val s = server()
    assert(s.signal(1L, s.issueToken(1L, 0, labelA)).isRight) // old round
    assert(s.signal(100L, s.issueToken(100L, 1, labelA)).isRight) // far ahead -> evicts round 1
    assert(s.digest(1L, labelA).isEmpty) // round 1 dropped (never fetched)
    assert(s.digest(100L, labelA).get(1)) // current round retained
    assert(s.retainedRounds == 1)

  test("forged token is rejected (cannot flood/impersonate, FR-003)"):
    val s = server()
    assert(s.signal(R, Array.fill[Byte](40)(0)).isLeft)

  test("tampered sealed token is rejected (AEAD authentication)"):
    val s = server()
    val tok = s.issueToken(R, 2, labelA)
    tok(tok.length - 1) = (tok(tok.length - 1) ^ 0x01).toByte
    assert(s.signal(R, tok).isLeft)
    assert(s.digest(R, labelA).isEmpty)

  test("concurrent signals under one (round,label) all survive (atomic OR)"):
    import scala.concurrent.{Await, Future}
    import scala.concurrent.ExecutionContext.Implicits.global
    import scala.concurrent.duration.*
    val s = server()
    val toks = (0 until 200).map(i => s.issueToken(R, i, labelA))
    Await.result(Future.sequence(toks.map(t => Future(s.signal(R, t)))), 30.seconds)
    assert(s.digest(R, labelA).popcount == 200)
