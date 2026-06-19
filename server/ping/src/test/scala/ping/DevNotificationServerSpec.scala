package ping

import crypto.Crypto
import privacy.Privacy
import org.scalatest.funsuite.AnyFunSuite

class DevNotificationServerSpec extends AnyFunSuite:

  private def server(): DevNotificationServer =
    DevNotificationServer(Array.tabulate(Crypto.KeyBytes)(_.toByte))

  private val labelA = "alice".getBytes
  private val labelB = "bob".getBytes

  test("dev notification server is labeled and never metadata-private (Constitution IV)"):
    val s = server()
    assert(!s.metadataPrivate)
    assert(s.label == Privacy.DevLabel)

  test("a sealed token flips exactly its own bit; digest reveals presence not identity"):
    val s   = server()
    val tok = s.issueToken(bitPosition = 5, labelA)
    assert(s.signal(tok).isRight)
    val d = s.digest(labelA)
    assert(d.get(5) && d.popcount == 1)

  test("two buddies under one label OR into a 2-bit digest (FR-004)"):
    val s = server()
    assert(s.signal(s.issueToken(3, labelA)).isRight)
    assert(s.signal(s.issueToken(9, labelA)).isRight)
    val d = s.digest(labelA)
    assert(d.get(3) && d.get(9) && d.popcount == 2)

  test("no waiting mail yields an all-zero carrier digest (uniformity, FR-012)"):
    assert(server().digest(labelA).isEmpty)

  test("labels isolate clients: a signal for A does not appear in B's digest"):
    val s = server()
    assert(s.signal(s.issueToken(7, labelA)).isRight)
    assert(s.digest(labelB).isEmpty)

  test("forged token is rejected (cannot flood/impersonate, FR-003)"):
    val s = server()
    assert(s.signal(Array.fill[Byte](40)(0)).isLeft)

  test("tampered sealed token is rejected (AEAD authentication)"):
    val s   = server()
    val tok = s.issueToken(2, labelA)
    tok(tok.length - 1) = (tok(tok.length - 1) ^ 0x01).toByte
    assert(s.signal(tok).isLeft)
    assert(s.digest(labelA).isEmpty)
