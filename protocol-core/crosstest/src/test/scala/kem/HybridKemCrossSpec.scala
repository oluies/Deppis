package kem

import org.scalatest.funsuite.AnyFunSuite

/** SINGLE-SOURCED cross-platform tests for the hybrid KEM [[HybridKem]]. This one file is compiled
  * into BOTH builds — the JVM `protocolCore` (delegating adapter over the vetted `crypto.HybridKem`:
  * X25519 via JCA + ML-KEM-768 via liboqs) AND the Scala.js `protocolCoreJS` (`@noble/curves` +
  * `@noble/post-quantum` + `@noble/hashes`) — via a shared entry in each project's
  * `Test / unmanagedSourceDirectories` (see build.sbt). `kem.HybridKem` resolves to the platform
  * object of whichever build compiles this file, so ONE copy of the pinned KAT vectors and the
  * platform-agnostic assertions guards both platforms with zero lockstep-drift hazard.
  *
  * ==Cross-platform interop KAT — why this proves the two hybrid KEMs interoperate==
  * The strongest test is the shared decapsulation vector: a fixed `(secret 2464, ciphertext 1120)`
  * GENERATED ONCE on the JVM (`kem.HybridKem.keypair` + `encaps`) and pinned VERBATIM here. If the
  * JS `decaps` reproduces the same 32-byte shared secret the JVM produced, the two hybrid KEMs agree
  * on that vector. This is valid because every leg is independently proven cross-platform:
  *   - ML-KEM-768: `@noble/post-quantum` ≡ liboqs ≡ FIPS 203 — the ACVP decapsulation KAT in
  *     `KemJsSpec` / `crypto.OqsKatSpec` (#75);
  *   - X25519: `@noble/curves` ≡ JCA — the RFC 7748 KAT in `X25519JsSpec` / `x25519.X25519Spec`;
  *   - the combiner: byte-identical SHA-256 construction — the `fd00…69d8` KAT below.
  * Since decaps is `combine(X25519(sk_static, eph_pub), ML-KEM.decaps(ct, sk_ml), …)` and all three
  * components match across platforms, a shared vector verifying on both is deterministic proof of
  * interop. NOTE (honesty): this is NOT a live cross-process handshake — it is a pinned known-answer
  * test, the same methodology used to pin the ACVP ML-KEM vectors. */
class HybridKemCrossSpec extends AnyFunSuite:

  private def hex(s: String): Array[Byte] =
    s.filterNot(_.isWhitespace).grouped(2).map(Integer.parseInt(_, 16).toByte).toArray

  // Mask to unsigned before formatting: Scala.js `"%02x".format(negativeByte)` sign-extends to
  // "ffffffXX" (the JVM Formatter does not), so mask explicitly for cross-platform-stable hex.
  private def toHex(a: Array[Byte]): String = a.map(b => "%02x".format(b & 0xff)).mkString

  test("round-trip: keypair -> encaps -> decaps agree; sizes match the contract"):
    val (pub, secret) = HybridKem.keypair()
    assert(pub.length == HybridKem.PublicKeyBytes, "public key = 1216")
    assert(secret.length == HybridKem.SecretKeyBytes, "secret = 2464")
    val (ct, ssEnc) = HybridKem.encaps(pub)
    assert(ct.length == HybridKem.CiphertextBytes, "ciphertext = 1120")
    assert(ssEnc.length == HybridKem.SharedSecretBytes, "shared secret = 32")
    val ssDec = HybridKem.decaps(ct, secret)
    assert(ssDec.sameElements(ssEnc), "encaps and decaps must derive the same secret")

  test("combiner KAT: fixed inputs pin the exact 32-byte SHA-256 output (JVM<->JS interop)"):
    // Byte-identical to crypto.HybridKemSpec's KAT — pins Label, field order
    // (label ++ ssX ++ ssMl ++ eph ++ peer ++ ct), and the digest across all implementations. A
    // silent drift here would break JVM<->JS interop while passing round-trips.
    def fill(n: Int, v: Int): Array[Byte] = Array.fill(n)(v.toByte)
    val out = HybridKem.combine(
      ssX25519 = fill(32, 0x11),
      ssMlKem = fill(32, 0x22),
      ephemeralX25519Raw = fill(32, 0x33),
      peerX25519Raw = fill(32, 0x44),
      mlkemCiphertext = fill(1088, 0x55)
    )
    assert(
      toHex(out) == "fd00ed12313e19b3c4241905c9904c4e7678df58de7f39d2a77e4a6a1f0769d8",
      s"combiner output drifted: ${toHex(out)}"
    )

  test("cross-platform interop KAT: fixed (secret, ciphertext) decaps to the pinned shared secret"):
    // Generated ONCE on the JVM (kem.HybridKem.keypair + encaps) and verified on BOTH platforms here.
    val secret = hex(
      "8d9e827d198c6b5ec2d71fc396824af8eeb46844888614836683cd665864df2c" +
        "9ffbf8c37a253d30b57f616059649fc94dda921fa2c234894d85bf0433a13e09" +
        "f63289e5ca4e9d45acd401a2d9a305964a893cd08be2809a83e351909665ea98" +
        "a0a38662735212a3cb4514dc022fe52ad837cec19293de328edf15c138612f00" +
        "e08d99d0c443fb780e600550ecbe95b10fd7c51274c043603a7b3db61817a9a6" +
        "89eb63d1d1b3039bad76809a0d5c1453c75d8842554163a9733c259b16c13493" +
        "1d1a55c5b4b2c30e34074af62b9cf092e31b2054f72f075466b9cc88ce3b6b75" +
        "4295d0b50ccd9283e855c277752d42819fdd1618b66377d0457d585632fb2618" +
        "6b96204cf02a80a86249975254d53bf7b38b4514148cac49a1032082da321a51" +
        "35c1473ed8f65c37fb678234927a89777da8960c6225884507d0530ef43a8d86" +
        "d698167239e9544f4bf1c808a467fd025cd04719bd0b945cc9b02167a6a5ca16" +
        "c5430a3b0a9929d06816b732b3da7934998cdb839fdf52b1023a4ee088af8fc9" +
        "5ec866a62b5138a2db7d13a17719b075a526b8aba3a922b92078643b7cfbbf06" +
        "5b4ee4dc50d6309e07734bf158c3c0e7c641baccb07c026ff735bd692256d95e" +
        "3645402fa371dfdc7972d42c6a053247ea4069a28b39ec8c73123e041a1921d2" +
        "84c9744f438a94580519d3f769885852fc2247f2406b7799581d5c1c09f72f38" +
        "b94da78b1d769b3c01b885be4045c8f47ebcec783eb7b45f409a9ed472d9da37" +
        "5062c6f772a5e3b9a34dab373e070528ea39cf751e2bf049c3460326666bc7a6" +
        "75277a53f2cb5d1cc60822ca713f53ade9860880751efca17a5bb57c7f8b5e1c" +
        "fa0964f79e82e513c279526b5aa1bb837b48991a8d4cb75fa688c4a9aa8c0c5e" +
        "5538b4104bc247e29f656ba395618ce4991a592aca0f2a01b2a7b590dc98883a" +
        "a0abc24145e9cf095b924c67810b624b6d1599a394b238413ced94ac3ee1c1ef" +
        "39a629d04d1ba9750dc94ad855c7389a9c4c04307e3b2233e754e5673942a51b" +
        "fae6880416715fc22c6fa579d6d3cd4b957f4847552eec9d3e117c1fb11e178c" +
        "78562829e5803b64b732b75c1e9c22c50149852e383c4b5a356588187b7a360e" +
        "80c662574a951aa912595ea59c83018b28006a0923b6614414a48b7c50212aca" +
        "c93a7e41d208512ccc3e9a8364ba0af534c0748c405b20287f41a614791e7998" +
        "7b7cfc0d41663a4a89c60fd6a4aae3c8bc8c6a5392370c9a414669a07f951dcd" +
        "0453f493cf024b3ce04178c666399eabb8983c4b814b761ac939dfb4183591bb" +
        "4969cd03231275bc5f421849014bcabd88b4858143a6721230201d37d3b45002" +
        "962a5167e9d97560021588c20490782cd54107e867ce1c88c4f2895b581c0768" +
        "211343e80886e47597d794b3bb8bfaac79f4c8882b4173d09c2a6449c86e4c31" +
        "45c879dc598da0026d5679c7ce5c8f48c8ca76ab7eae88513be570ab5075ff71" +
        "35f1a5454950cc63fb65f6c7bb81510f74a79982fa1056f392e3a041db35b4c8" +
        "561f6c64280c349e5bf53b19899ef060590793a8a9ec280ea63e0ad42ca7fb82" +
        "d1fb67154cce4945b329170f95a2621d123b4313102212a72ed07c25889e171c" +
        "85e5e891d41c48cdf16725c98fe1847673bc7a9e934e03bcc54a33cd9af615f6" +
        "3bc3ffcc94ca3b85e5461591aa4c339613500a05b747a172662d3132cc2dd736" +
        "bec29b176ca69a7cb66d3b5a99f35d522b73d1d262a364cf32b716792850e677" +
        "2a779a96bc1b823af369d85b792605610b66917b9412d287ce402b7cb2352bcf" +
        "cc409a604f05ac6531f896db0468545c2d2b0b0de87986fe822464fb3894a39c" +
        "69b1a340f52fd8799ac7f223c90a4be4e02080443b36b714d9f4270b96c44031" +
        "2e4f027d8a29882284bb1fe4c7c04335b5c569926320ccb782ba8aa0008100ff" +
        "443e334761a85c8a71140f1f88a0c029b32f65ae4ca6cf851c258d479e13d005" +
        "a1192115eb1375990908e154eaaa59f1caa1a2d0b2a4c346f6ea3f3a5155e8aa" +
        "9aed7491361609effb4e5538614c031d7655460e0926a0281704926f59aa786b" +
        "a3312a5707413861f96257699aa0fd5654eba5a7d6164ab03b9570e89a0466a5" +
        "cff04258852af6451bd6c551adc201aa566417844b4a7ba947fa71238714680c" +
        "274d14252bb4344f3597ac134f69b005dd01862f851102133471e7b89a8bb31d" +
        "d18b3a691b1a5b7a59299175318a6f129c555135d3f5502f503568d367db90bc" +
        "65a813db9822cb987922d24c6e2a0fb4195185cb8fa10c3bdca5b5300278728b" +
        "948e9b80c28a98a1123a01295fbac23a688c9296128b708a43ae880ee0892004" +
        "5c79b51c5c5e828f2ed0242f2aac596a97d28258cf1b3b8dc6555d31997cf95a" +
        "e2614667aa7cc13338114469243a0242428a799236314b16e76bc6cca171d775" +
        "1984f2c85c06250d97bea6710da9009818ac5ca97c0a1fa257fbda833ee7af44" +
        "3a29e7c365123a141f3a466cc1ca67b0ae85ac0562784ee3b53a874811f6428d" +
        "ae484ab6a73f155c1a1291b0db733df57397b77994daf158a5624be4f273c1b7" +
        "3fcff4961312549ddb7eae2665937a166decab520c2d33c14359218d5c4b093c" +
        "b63d136614ec5a4b6ada332da3cf705260bca48f4bf30ba640ab6017844d5571" +
        "eb2670215a4a2abb9b86f1cdade2b5f3e37b0d944bcbe4300a63b7b07c181842" +
        "c29a3c5c313410e3b037f8f69427649ffc007e6444aa3d271d3a79ae4c784df7" +
        "3473d81251f9110a648b3dec4510b6987b36659ccc29c4f989b8e7048059a70f" +
        "a7105b05f015a17a38f2b287c0b42830b222829333fa3a20386250e2acb47026" +
        "3e87a1264d3ab6b5c51300504efacc1f51b43c9e49744580ca7a4c1837fc6370" +
        "a833f2123c2d9b48cc13a464c4c30665b451cb62bad90a7cc7a3f09a0646a318" +
        "14c16f08ba4662857d96f5cd74568be830bd20a776b885ba62442c31f7547e3a" +
        "492e707ceacba55a295d29ea196c01175bc976e9233ca65602cda5c884727d43" +
        "32b160e13c5ac655ee22046281488417267c6965c945593d26495de5674cc118" +
        "d19198bdf46a60287fa9f7457d1c0c43614ead6301edf688b70994e2c0900743" +
        "04c3646600bda85762be8194b22ea4172ed94b4f00792a9925ca784ebb902bad" +
        "98c6713b3738b7173d698714441dabb2143a857740bc3079052de87283279b7f" +
        "c6d45f980314e308314b7971e35a2021eb9002aca4dcd1788dc8b6b8d0027d75" +
        "c5533b5347e53688a3b8de91a61f8402698835a936a5fdd50199992a907bcdce" +
        "9146f7c6064e0802fc09354e445821465b7cb8812425b9d24284cca0361ce4b2" +
        "accbfd6a3d0664ec8afb4383333d924120135d656f0d2b8a87c693e1322b26cb" +
        "1bfb1309f1957252cccf4cf6ce20114ca3b283006bb34d862aa3ff35d887e111" +
        "fa85ec52b195b0bf503a86bafd5444b12ee6a634d6e3b426dc4bff4e9162814f"
    )
    val ciphertext = hex(
      "3f5e7404e18a9b771692fdd9125844f744b1df5fc412ae4235c5cc5eb2a72310" +
        "bb3d9b4f69fa0bdfe1e4cddf155111dd7d5e0e39d93f8a2ece61b338cf9bb170" +
        "d47edc8a236dfc1aef1a5d95e9ca3aa667300aa8b9bd54b6e7d4fe7c928a212e" +
        "884b34cff09e50bff1e84f4fa557d623b9e2e6058b8b647f0edfb3484e4a6b2f" +
        "b1d72778841fd61b75ef400c9bd5f5f44f57878ac2374548fdcdb2175d473c64" +
        "98113f7869baa82f5c879c06017d896a00e38fa2f0354cb6f270c5bbf109cddd" +
        "ecc9747e5a65aea55d3f6f167ecbdd852aec0f880d8389d3502e11b2be92d054" +
        "1636eaaad6c865a5cf5f7e751509b7af3d993ee793754de6efe66e010dcc3e8c" +
        "9d45633a6bb08a5b1fa2c1960fd0ca3eeb66a153345973f7a8804e693c731ae0" +
        "93a3fb9a19fd6fc906f46a55da9ed119706573986556e1bc0918cec70edd9357" +
        "c88c2bf992f5306bd025178d589906c2078e318ea823ac3d726eba9ed4da36f3" +
        "79ebf6299ee49110dadc30c1dd5ec19c63b5c96b4478e37409c0ce8fb7780cd9" +
        "719b02468bb253cf9be8b072ab534f8c5ce5a012baf245bc9b05082b8957c1bd" +
        "9fcce54b4252f69cccbc83ef2c8725e25579667f0cdb736d42876eb91618f958" +
        "ee0ee743768b9e83022aa964a979095207f596369728607a670721fdb43d8401" +
        "aee0f9a78133c3369840085a93652c0dec8832fc67d34231b6349f4977842a09" +
        "e96c74bbb6fff09941990ec3d64dc53e7768e5208234518002643ee58224f9bf" +
        "ab26154f35d0cad812fb3469f6d8b5a042faa33548c1bba75375755d4ace531d" +
        "f04bea51d7e5118820ecc70f734ae33d0685657ada6df15af758d316af76bfeb" +
        "924924b629424e02c7c4c702136d6b31422f668f1162ba36ca12528ef2a19f90" +
        "753a833a9e7a9e62c54ba66036879cd01ee4d617b136a67a0a22dd87926bc1a6" +
        "95f560660d4f8c749012c4ddf737c06575b5b2c5172cc90ece31b6134cd85981" +
        "846661867125de8cb9e2f104390ef08b2dd72591c687ac11d8480668151058d6" +
        "1fa85211523eac0610c15c987a5c32e7341597dad301b1ec2e12b5532e09a852" +
        "ec96d465cf1c2e47023a7d6177aa43c47a5a1b54e2432138fb3db52ac22afcb5" +
        "268e42a0b3732a0570e40a9493a9f8cad2735066f6103a56030947a2e278b4e2" +
        "6a24249fc251c9f3b2369e0111ad9797f3fa783ad910394a1fb4f1e86a2a117f" +
        "f63ec16d2a48921a0ef42848cba6f3446de6070f14119dd93da4a053e10d8ab4" +
        "31d43dfffb9df4dd888532d40b5dcfe68575678686fd015038d9ac3dcab93529" +
        "87cdc92cd5b46cc709f4d5142ba09fb0963daed5674752af7767395a63d7459d" +
        "5f16fc49c7af8252f2d65e0f538afa0df3e8e84d9affaa1453e26470e53dca4c" +
        "7c69500b9e77a6732959ae1d16199f1e37229e41b7d4c01eeacd7b12381242b4" +
        "496dcad283de436ebec7516e16625ed9251c1734930df4afecd6cd4488b3ece4" +
        "9a7d69bcb81eb14eb6166a65e627d907d090d2191a3c19aefe19d2ece8eb71ad" +
        "d11034ed47555d28466630d319c451e2553c94f7c9576afd4de882326a75a3c9"
    )
    val expectedSs =
      hex("e79beacc5bbe410d44f2c5994d1d612b8a5a4748a6b47ce0916d6a488c412b2c")
    assert(secret.length == HybridKem.SecretKeyBytes)
    assert(ciphertext.length == HybridKem.CiphertextBytes)
    assert(
      HybridKem.decaps(ciphertext, secret).sameElements(expectedSs),
      "decaps of the pinned interop vector must reproduce the shared secret"
    )

  test("decaps rejects a wrong-length ciphertext"):
    val (_, secret) = HybridKem.keypair()
    assertThrows[IllegalArgumentException](HybridKem.decaps(Array.emptyByteArray, secret))
    assertThrows[IllegalArgumentException](
      HybridKem.decaps(new Array[Byte](HybridKem.CiphertextBytes - 1), secret)
    )

  test("decaps rejects a wrong-length secret"):
    val (pub, secret) = HybridKem.keypair()
    val (ct, _) = HybridKem.encaps(pub)
    assertThrows[IllegalArgumentException](HybridKem.decaps(ct, Array.emptyByteArray))
    assertThrows[IllegalArgumentException](
      HybridKem.decaps(ct, secret.take(HybridKem.SecretKeyBytes - 1))
    )

  test("encaps rejects a wrong-length peer public key"):
    assertThrows[IllegalArgumentException](HybridKem.encaps(Array.emptyByteArray))
    assertThrows[IllegalArgumentException](
      HybridKem.encaps(new Array[Byte](HybridKem.PublicKeyBytes + 1))
    )

  test("encaps rejects a hybrid public key whose X25519 prefix is a low-order (all-zero) point"):
    // The all-zero X25519 u-coordinate is an order-1 point: the ECDH result is all-zero regardless of
    // the ephemeral scalar (non-contributory). The hybrid encaps MUST reject it (IllegalArgumentException),
    // at the hybrid level — not only one layer down in the X25519 leg. Uniform on both platforms.
    val (pub, _) = HybridKem.keypair()
    val lowOrderPub = pub.clone()
    for i <- 0 until 32 do lowOrderPub(i) = 0.toByte
    assertThrows[IllegalArgumentException](HybridKem.encaps(lowOrderPub))

  test("encaps rejects a non-canonical peer X25519 component (u = p)"):
    // p = 2^255 - 19 encodes little-endian as ed ff*30 7f. u = p is >= p, so the canonicality check
    // rejects it (a peer that reduced mod p would otherwise silently disagree on the classical leg).
    val (pub, _) = HybridKem.keypair()
    val nonCanonical = pub.clone()
    nonCanonical(0) = 0xed.toByte
    for i <- 1 until 31 do nonCanonical(i) = 0xff.toByte
    nonCanonical(31) = 0x7f.toByte
    assertThrows[IllegalArgumentException](HybridKem.encaps(nonCanonical))

  test("decaps rejects a ciphertext whose eph-X25519 prefix is a low-order (all-zero) point"):
    // The MORE security-relevant direction: a responder decapsulating hostile ciphertext. The
    // attacker controls the first 32 bytes (the ephemeral X25519 public). An all-zero (order-1)
    // prefix is non-contributory and MUST be rejected BEFORE ML-KEM decaps, uniformly on both
    // platforms (the remaining ML-KEM ct region is irrelevant — rejection is on the X25519 leg).
    val (_, secret) = HybridKem.keypair()
    val ct = new Array[Byte](HybridKem.CiphertextBytes) // eph-X25519 prefix = 32 zero bytes
    assertThrows[IllegalArgumentException](HybridKem.decaps(ct, secret))

  test("decaps rejects a ciphertext whose eph-X25519 prefix is non-canonical (u = p)"):
    val (_, secret) = HybridKem.keypair()
    val ct = new Array[Byte](HybridKem.CiphertextBytes)
    ct(0) = 0xed.toByte
    for i <- 1 until 31 do ct(i) = 0xff.toByte
    ct(31) = 0x7f.toByte
    assertThrows[IllegalArgumentException](HybridKem.decaps(ct, secret))

  test("tampering either ciphertext leg changes the decapsulated secret (transcript binding)"):
    // The combiner binds BOTH the eph-X25519 prefix and the ML-KEM ciphertext into the derived secret,
    // so a bit flip in EITHER region yields a different shared secret (the two sides then fail to agree
    // rather than silently sharing a key that reflects only one leg).
    val (pub, secret) = HybridKem.keypair()
    val (ct, ss) = HybridKem.encaps(pub)
    val ctX = ct.clone()
    ctX(0) = (ctX(0) ^ 0x01).toByte
    assert(
      !HybridKem.decaps(ctX, secret).sameElements(ss),
      "a bit flip in the eph-X25519 prefix must change the derived secret"
    )
    val ctMl = ct.clone()
    ctMl(HybridKem.CiphertextBytes - 1) = (ctMl(HybridKem.CiphertextBytes - 1) ^ 0x01).toByte
    assert(
      !HybridKem.decaps(ctMl, secret).sameElements(ss),
      "a bit flip in the ML-KEM ciphertext must change the derived secret"
    )
