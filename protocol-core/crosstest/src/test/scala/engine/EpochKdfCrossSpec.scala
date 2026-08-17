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

  // Hex via PqTestKit.hex — same `engine` package + same crosstest root, so it is already in scope
  // and already carries the unsigned-mask fix (Scala.js sign-extends "%02x".format(negativeByte) to
  // "ffffffXX"). One hex helper per package: a second copy is exactly the drift crosstest prevents.
  private def toHex(a: Array[Byte]): String = PqTestKit.hex(a)

  private def fill(n: Int, v: Int): Array[Byte] = Array.fill(n)(v.toByte)

  private val rk = fill(32, 0x11)
  private val ss = fill(32, 0x22)

  test("KAT: kdfEpoch(rk=32x11, ss=32x22) pins label 'dr/pq-epoch' + order + digest (JVM<->JS)"):
    assert(
      toHex(EpochKdf.kdfEpoch(rk, ss)) ==
        "fce745321bfc4b4e647182f6f47b87a5ff6e73edd99972ee29b94968b9cd9df4",
      "epoch-fold output drifted — JVM<->JS epoch agreement would break"
    )

  // The confirm tags are plain domain-separated HMACs over a 32-byte epoch key. The vectors below
  // pin the LABELS and the digest; they are keyed on `kdfEpoch(rk, ss)` purely because that is the
  // 32-byte value the Phase 1 vectors were generated from, and they are kept byte-identical so the
  // label pin never moves. What the LIVE protocol keys them on is `ss` — see the `ss`-keyed vectors
  // below and `EpochKdf`'s object doc ("What the tags are keyed on").
  test("KAT: initiator confirm tag pins label 'dr/pq-epoch-confirm/i' (JVM<->JS)"):
    val key = EpochKdf.kdfEpoch(rk, ss)
    assert(
      toHex(EpochKdf.epochConfirmTagInitiator(key)) ==
        "3bb59a4eb4d38e64fd0189a218af3de9205be902880e32783f859a299e89abd4",
      "initiator epoch-confirm tag drifted"
    )

  test("KAT: responder confirm tag pins label 'dr/pq-epoch-confirm/r' (JVM<->JS)"):
    val key = EpochKdf.kdfEpoch(rk, ss)
    assert(
      toHex(EpochKdf.epochConfirmTagResponder(key)) ==
        "5a52cbb40ede361a2bc5d6496e12b7465f7a0754af0fbad23af811f2da363e74",
      "responder epoch-confirm tag drifted"
    )

  test("KAT: the PHASE 3 keying — tags over the KEM SHARED SECRET itself (JVM<->JS)"):
    // This is the call shape `Engine`'s rekey state machine actually makes: the per-direction tags
    // are keyed on the 32-byte hybrid-KEM shared secret, NOT on the folded root (which neither peer
    // holds while the tags are in flight — see EpochKdf's object doc). Pinning it here means the
    // interop contract covers what the protocol DOES, not only what Phase 1 could reach.
    assert(
      toHex(EpochKdf.epochConfirmTagInitiator(ss)) ==
        "49fca871a1803f788b3a2bae2a793230663fc3290694a5f6ba1384a4870f7d4a",
      "initiator epoch-confirm tag over `ss` drifted — JVM<->JS rekey confirmation would break"
    )
    assert(
      toHex(EpochKdf.epochConfirmTagResponder(ss)) ==
        "dac51684562280e935567b59020cc19259e92d4d23ca831f90871db228c62136",
      "responder epoch-confirm tag over `ss` drifted — JVM<->JS rekey confirmation would break"
    )
    // Anti-reflection at the real keying: the two directions never collide.
    assert(
      !EpochKdf.epochConfirmTagInitiator(ss).sameElements(EpochKdf.epochConfirmTagResponder(ss))
    )

  // ============================================================ edge inputs + a CHAINED fold
  // The vectors above pin one interior `(rk, ss)` pair. These widen the cross-platform contract to
  // the two byte patterns where a platform difference is most likely to surface — all-zero and
  // all-0xff — because 0xff is exactly where Scala.js's signed `Byte` bites (the sign-extension bug
  // `PqTestKit.hex` exists to mask), and all-zero is what a wiped or unset buffer looks like, so a
  // fold that silently accepted one would go unnoticed without a pinned digest. All generated on
  // the JVM alongside the originals.

  private val zero = fill(32, 0x00)
  private val ones = fill(32, 0xff)

  test("KAT: kdfEpoch at the edges — all-zero and all-0xff inputs (JVM<->JS)"):
    assert(
      toHex(EpochKdf.kdfEpoch(zero, zero)) ==
        "a05252b48a7727360da9472a0784e748cc4534fe987a80232a08f4c97bff375c",
      "all-zero epoch fold drifted"
    )
    assert(
      toHex(EpochKdf.kdfEpoch(ones, ones)) ==
        "c79dbcea4a200fc69d8626f68046fca0b4c04a60932f5e24a0c6c807013c481c",
      "all-0xff epoch fold drifted — the likeliest place for a JS Byte sign-extension bug to land"
    )

  test("KAT: kdfEpoch's argument ORDER is pinned at the edges (rk,ss) != (ss,rk)"):
    // Swapping the two 32-byte arguments must not be silently absorbed. Distinct pinned digests say
    // so as a KAT rather than as a round-trip property, so a refactor that transposed them would
    // fail HERE with a concrete expected value rather than somewhere downstream.
    assert(
      toHex(EpochKdf.kdfEpoch(zero, ones)) ==
        "654d4ff9dcd918d90bf668201e3a440b15b825ee48995a253bf34bc37079e7fc",
      "kdfEpoch(zero, ones) drifted"
    )
    assert(
      toHex(EpochKdf.kdfEpoch(ones, zero)) ==
        "be798a1eccff5aa9192bcb34c6b649b6b1bc734a7d2644fa6204664e38d1aa48",
      "kdfEpoch(ones, zero) drifted"
    )
    assert(
      !EpochKdf.kdfEpoch(zero, ones).sameElements(EpochKdf.kdfEpoch(ones, zero)),
      "the two arguments are not interchangeable"
    )

  test("KAT: confirm tags at the edges — all-zero and all-0xff epoch secrets (JVM<->JS)"):
    assert(
      toHex(EpochKdf.epochConfirmTagInitiator(zero)) ==
        "214a7880b2cb7b0e885bd95a0963a51408903f4832234b94feb107c280d4de71",
      "all-zero /i tag drifted"
    )
    assert(
      toHex(EpochKdf.epochConfirmTagResponder(zero)) ==
        "846031c89f2a1c13bcc072eb1f817a2fbed4e403cc64e4af0c2261b11ecc563a",
      "all-zero /r tag drifted"
    )
    assert(
      toHex(EpochKdf.epochConfirmTagInitiator(ones)) ==
        "527c249640bb863bc11847d17874248839babc94ccf860b88e0f989f6ad914b5",
      "all-0xff /i tag drifted"
    )
    assert(
      toHex(EpochKdf.epochConfirmTagResponder(ones)) ==
        "6f27e60931882cf4a8a0b93337f3a7a15ea66db658a6ebb0ac61b5f737aa74be",
      "all-0xff /r tag drifted"
    )

  test("KAT: a CHAINED two-epoch fold — the multi-epoch root is pinned across platforms"):
    // A pair that folds twice must agree on the SECOND root as well, and nothing above pins it: the
    // single-fold vectors would still pass if the second fold re-seeded from the ORIGINAL root
    // instead of the folded one. This walks the same path `DoubleRatchet.advanceRoot` walks across
    // two epochs (design §4.1, §8.2 "a later epoch composes onto the folded root").
    val ss2 = fill(32, 0x33)
    val fold1 = EpochKdf.kdfEpoch(rk, ss)
    assert(
      toHex(fold1) == "fce745321bfc4b4e647182f6f47b87a5ff6e73edd99972ee29b94968b9cd9df4",
      "the first fold must still match the original single-fold vector"
    )
    assert(
      toHex(EpochKdf.kdfEpoch(fold1, ss2)) ==
        "0763353705a2b5842b2ab2673a8e384878e64b351c5605ea7003c074a7fe0a38",
      "the second epoch's root drifted — a twice-folded JVM and JS pair would part company"
    )
    // And the composition is not idempotent or self-cancelling: epoch 2's root is its own value.
    assert(!EpochKdf.kdfEpoch(fold1, ss2).sameElements(fold1))
    assert(!EpochKdf.kdfEpoch(fold1, ss2).sameElements(rk))

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

  test("the fold MOVES the root: kdfEpoch(rk, ss) != rk"):
    // The property Phase 3's security argument rests on — a degenerate fold that returned `rk`
    // (or ignored `ss`) would leave the epoch un-hardened. Mirrors PqPairingJsSpec's
    // `!pqContentRoot(base, ss).sameElements(base)` check for the pairing-time fold.
    assert(!EpochKdf.kdfEpoch(rk, ss).sameElements(rk))

  test("KeyBytes matches the hybrid KEM's shared-secret width (documented invariant, enforced)"):
    // EpochKdf.KeyBytes is a bare literal whose scaladoc claims equality with the KEM output width.
    // Pin it: if the hybrid combiner's width ever changes, fail HERE rather than as a runtime
    // IllegalArgumentException from kdfEpoch in Phase 3.
    assert(EpochKdf.KeyBytes == kem.HybridKem.SharedSecretBytes)

  test("independence: a different KEM shared secret yields a different folded root"):
    assert(!EpochKdf.kdfEpoch(rk, ss).sameElements(EpochKdf.kdfEpoch(rk, fill(32, 0x23))))

  test("independence: a different live root yields a different folded root"):
    assert(!EpochKdf.kdfEpoch(rk, ss).sameElements(EpochKdf.kdfEpoch(fill(32, 0x12), ss)))

  test("ANTI-REFLECTION: the /i and /r tags of one epoch key differ (domain separation)"):
    // Mirrors PqReflectionCrossSpec's same-root check for the pairing tags: over the SAME folded
    // root, ONLY the direction label differs, so distinct outputs pin the domain separation that
    // stops a tag observed in one direction being reflected back as the other's.
    val rkEpoch = EpochKdf.kdfEpoch(rk, ss)
    assert(
      !EpochKdf
        .epochConfirmTagInitiator(rkEpoch)
        .sameElements(EpochKdf.epochConfirmTagResponder(rkEpoch)),
      "distinct direction labels must yield distinct tags on the same epoch key"
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

  test("confirm tags reject a wrong-length epoch key"):
    assertThrows[IllegalArgumentException](
      EpochKdf.epochConfirmTagInitiator(Array.emptyByteArray)
    )
    assertThrows[IllegalArgumentException](EpochKdf.epochConfirmTagInitiator(fill(31, 0x11)))
    assertThrows[IllegalArgumentException](
      EpochKdf.epochConfirmTagResponder(Array.emptyByteArray)
    )
    assertThrows[IllegalArgumentException](EpochKdf.epochConfirmTagResponder(fill(33, 0x11)))
