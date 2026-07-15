package engine

import org.scalatest.funsuite.AnyFunSuite

/** SINGLE-SOURCED cross-platform KAT spec for [[EpochKdf]] — compiled into BOTH the JVM
  * `protocolCore` and the Scala.js `protocolCoreJS` builds via the shared
  * `Test / unmanagedSourceDirectories` entry (see build.sbt).
  *
  * The pinned vectors were generated ONCE on the JVM (JCA HMAC-SHA256, the same primitive
  * `kdf.Kdf` delegates to) and hardcoded here. Asserting them on BOTH platforms pins the exact
  * label strings (`"dr/pq-epoch"`, `"dr/pq-epoch-confirm/i"`, `"dr/pq-epoch-confirm/r"`), the
  * `label ‖ ss` concatenation order, and the digest across JVM/JS FOREVER — this is the interop
  * contract for the continuous-PQ-ratchet epoch fold (design/continuous-pq-ratchet.md §4, Phase 1).
  * A silent drift in any of them would break JVM<->JS epoch agreement while round-trip tests
  * still passed. */
class EpochKdfCrossSpec extends AnyFunSuite:

  // Mask to unsigned before formatting: Scala.js `"%02x".format(negativeByte)` sign-extends to
  // "ffffffXX" (the JVM Formatter does not), so mask explicitly for cross-platform-stable hex.
  private def toHex(a: Array[Byte]): String = a.map(b => "%02x".format(b & 0xff)).mkString

  private def fill(n: Int, v: Int): Array[Byte] = Array.fill(n)(v.toByte)

  private val rk = fill(32, 0x11)
  private val ss = fill(32, 0x22)

  test("KAT: kdfEpoch(rk=32x11, ss=32x22) pins label 'dr/pq-epoch' + order + digest (JVM<->JS)"):
    assert(
      toHex(EpochKdf.kdfEpoch(rk, ss)) ==
        "fce745321bfc4b4e647182f6f47b87a5ff6e73edd99972ee29b94968b9cd9df4",
      "epoch-fold output drifted — JVM<->JS epoch agreement would break"
    )

  test("KAT: initiator confirm tag pins label 'dr/pq-epoch-confirm/i' (JVM<->JS)"):
    val rkEpoch = EpochKdf.kdfEpoch(rk, ss)
    assert(
      toHex(EpochKdf.epochConfirmTagInitiator(rkEpoch)) ==
        "3bb59a4eb4d38e64fd0189a218af3de9205be902880e32783f859a299e89abd4",
      "initiator epoch-confirm tag drifted"
    )

  test("KAT: responder confirm tag pins label 'dr/pq-epoch-confirm/r' (JVM<->JS)"):
    val rkEpoch = EpochKdf.kdfEpoch(rk, ss)
    assert(
      toHex(EpochKdf.epochConfirmTagResponder(rkEpoch)) ==
        "5a52cbb40ede361a2bc5d6496e12b7465f7a0754af0fbad23af811f2da363e74",
      "responder epoch-confirm tag drifted"
    )

  test("determinism: same (rk, ss) folds to the same root; tags are deterministic too"):
    assert(EpochKdf.kdfEpoch(rk, ss).sameElements(EpochKdf.kdfEpoch(rk, ss)))
    val rkEpoch = EpochKdf.kdfEpoch(rk, ss)
    assert(
      EpochKdf
        .epochConfirmTagInitiator(rkEpoch)
        .sameElements(EpochKdf.epochConfirmTagInitiator(rkEpoch))
    )
    assert(
      EpochKdf
        .epochConfirmTagResponder(rkEpoch)
        .sameElements(EpochKdf.epochConfirmTagResponder(rkEpoch))
    )

  test("independence: a different KEM shared secret yields a different folded root"):
    assert(!EpochKdf.kdfEpoch(rk, ss).sameElements(EpochKdf.kdfEpoch(rk, fill(32, 0x23))))

  test("independence: a different live root yields a different folded root"):
    assert(!EpochKdf.kdfEpoch(rk, ss).sameElements(EpochKdf.kdfEpoch(fill(32, 0x12), ss)))

  test("ANTI-REFLECTION: the /i and /r tags of one rkEpoch differ (domain separation)"):
    // Mirrors PqReflectionCrossSpec's same-root check for the pairing tags: over the SAME folded
    // root, ONLY the direction label differs, so distinct outputs pin the domain separation that
    // stops a tag observed in one direction being reflected back as the other's.
    val rkEpoch = EpochKdf.kdfEpoch(rk, ss)
    assert(
      !EpochKdf
        .epochConfirmTagInitiator(rkEpoch)
        .sameElements(EpochKdf.epochConfirmTagResponder(rkEpoch)),
      "distinct direction labels must yield distinct tags on the same rkEpoch"
    )

  test("output sizes: fold and both tags are 32 bytes (HMAC-SHA256)"):
    val rkEpoch = EpochKdf.kdfEpoch(rk, ss)
    assert(rkEpoch.length == EpochKdf.KeyBytes)
    assert(EpochKdf.epochConfirmTagInitiator(rkEpoch).length == EpochKdf.KeyBytes)
    assert(EpochKdf.epochConfirmTagResponder(rkEpoch).length == EpochKdf.KeyBytes)

  test("kdfEpoch rejects a wrong-length rk"):
    assertThrows[IllegalArgumentException](EpochKdf.kdfEpoch(Array.emptyByteArray, ss))
    assertThrows[IllegalArgumentException](EpochKdf.kdfEpoch(fill(31, 0x11), ss))
    assertThrows[IllegalArgumentException](EpochKdf.kdfEpoch(fill(33, 0x11), ss))

  test("kdfEpoch rejects a wrong-length kemSharedSecret"):
    assertThrows[IllegalArgumentException](EpochKdf.kdfEpoch(rk, Array.emptyByteArray))
    assertThrows[IllegalArgumentException](EpochKdf.kdfEpoch(rk, fill(31, 0x22)))
    assertThrows[IllegalArgumentException](EpochKdf.kdfEpoch(rk, fill(33, 0x22)))

  test("confirm tags reject a wrong-length rkEpoch"):
    assertThrows[IllegalArgumentException](
      EpochKdf.epochConfirmTagInitiator(Array.emptyByteArray)
    )
    assertThrows[IllegalArgumentException](EpochKdf.epochConfirmTagInitiator(fill(31, 0x11)))
    assertThrows[IllegalArgumentException](
      EpochKdf.epochConfirmTagResponder(Array.emptyByteArray)
    )
    assertThrows[IllegalArgumentException](EpochKdf.epochConfirmTagResponder(fill(33, 0x11)))
