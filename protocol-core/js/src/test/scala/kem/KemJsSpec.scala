package kem

import org.scalatest.funsuite.AnyFunSuite

/** Scala.js (Node) tests for the JS ML-KEM-768 facade [[Kem]], which wraps the audited
  * `@noble/post-quantum` library (Constitution I: no hand-rolled crypto).
  *
  * The crux is an **interoperability** known-answer test: the JS `noble` side reproduces the EXACT
  * NIST ACVP ML-KEM-768 decapsulation vector that the JVM `liboqs` side pins in
  * `crypto.OqsKatSpec` (tcId=89). Both matching the same FIPS 203 vector proves
  * JS-noble ≡ JVM-liboqs ≡ FIPS 203, i.e. the two implementations interoperate.
  *
  * ACVP source (same as `crypto.OqsKatSpec`): https://github.com/usnistgov/ACVP-server
  *   commit 15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0 (2026-04-16),
  *   `ML-KEM-encapDecap-FIPS203/internalProjection.json`, tgId=5 (decapsulation, ML-KEM-768, VAL),
  *   tcId=89 (reason "valid decapsulation"). These are public test vectors, not secrets. */
class KemJsSpec extends AnyFunSuite:

  // Local copy of the hex helper (mirrors `crypto.Kat.hex`) — the JVM `crypto` module is not on the
  // Scala.js classpath.
  private def hex(s: String): Array[Byte] =
    s.filterNot(_.isWhitespace).grouped(2).map(Integer.parseInt(_, 16).toByte).toArray

  // FIPS 203 ML-KEM-768 byte sizes.
  private val PublicKeyBytes = 1184
  private val SecretKeyBytes = 2400
  private val CiphertextBytes = 1088
  private val SharedSecretBytes = 32

  test(
    "ML-KEM-768 interop KAT: noble reproduces ACVP tcId=89 (valid decapsulation) — same vector as JVM OqsKatSpec"
  ):
    // dk (decapsulation/secret key), c (ciphertext), k (expected shared secret) copied verbatim from
    // crypto/src/test/scala/crypto/OqsKatSpec.scala (JVM/liboqs). If JS-noble decaps yields the same
    // k, JS-noble ≡ JVM-liboqs ≡ FIPS 203.
    val dk = hex(
      "cd4178d37142a91c7c597854df1b00e6147df88c58769b10b2a0b9bbd875fbe0" +
        "5ba228847d94c01ed4c57860339d6735b0f73788c495688395bcd51e4a36bcc1" +
        "5c1f3311162f8525557cbefa176d0fd8bcfff79843085b78c0ade09104ef7717" +
        "9927c37e739aaf7166cf6539c35097c0c3769051186572735b600c3eb07a4129" +
        "32650ca28d469d971b635d789c7fa608cbf819b7b7707291b9d22c25cbb55b0d" +
        "875ea903ce778c81a2e96bf6e96baa1a484e69524c644fc3d8c564140e32d4ae" +
        "0be1b1cc875cb4ec7764c498e5f01c04c9a41cf26bbdbc08c8e65bbda78a1c4c" +
        "0f362aac60e16f5d225454c2103a99758b0a93864c5f32179808d2a3855ac837" +
        "424e00f0a0a3055c07f5ab5bd04bc6950603960c29aa2b18c60c154a1022c32e" +
        "f59bb718e94adef990c045c27e3943c115c1d12a96eba503a01098e33673c98b" +
        "0421a7c71189530d08b4933912c37c1dcffb0a14a93a3ea6603a6035cc194c58" +
        "532d70e2b1b7b0ca5254bd7e010d7409ca58973c7f2062eac9ba196429d7da3d" +
        "d512c1d81182e17b7cec7c630659602c117f74008070e967f5f2293e9643cf70" +
        "a1f5a38069d0359d76a84c6846ba1a1bb91b5279864b9671c3896bb2d43278de" +
        "11b1a89b8f95f96a9ee815a6e7b063989a13d32080ca55d6c0421e6893b77632" +
        "dcf96d09f11ac5a740029273cbeb42c7c96fd36c1ee5589f61d70b57e93b8405" +
        "bdfaa460fa09be4a345b1d9939466806b9e462929240051b57dd614626a813ba" +
        "e8248a66c3c0bba804c52b345924a76cceed5468ec066dfd5a1770656f3a3b95" +
        "6531a6d4166cb36480235a4e62cc7a9dba2b45f464eb39002ba71a1211963a86" +
        "b16880c83b3bbbefa5a7bc4b31b2a69c09d9675a4b300a829f6a438649e26b82" +
        "a7cda8b80cb65986e47baa2f544cfde7b46cd17fcf1baae568bb28c8235c591a" +
        "e717bbc05c0cf86344e4627542639fabb11bb5f6c66bbab92f981cf6bb217942" +
        "b95f635e7ee75e314cc97f050276801b32bb86ca586e79c40638db283c3948da" +
        "4c7195c4421a1b3bc35886678c33eb0a5a52ba5c78b138d51cac85704bc0140c" +
        "a5b830117225cf4b0e363b8155eb4b83c7073bb20af2798376ba442d309577c6" +
        "2705c7a9172527faea9ce21b3863f32dae7a2d4b2314a376c14917563ae41de0" +
        "67007567a9e22bb30b834afef2b6b07846ac30b54104b8083248cd23afccf794" +
        "c1f59c1c62803b28873013296f5048f0637dff072529443ffecb57e12a7f0ce5" +
        "2cc8a85d258372dcbb5c0612735d1a6ba7e0ae02215547b28f5e77488b3a241e" +
        "abb2f3f19f89974b2d822604e74495a2091c363e9e88a7b80769d4492f6b7a7a" +
        "3bb27da60a1ba326882b7732c9118e545b6c4b79787225ba598378bad7b3cae9" +
        "0edc06cd0eac43a2c559cd554c5344a2751952f4b4bd2bb694016b41f65494a1" +
        "c750a9d9c338a25f5ae26bfe851540e6b84202114adb75986193737a5f28c2bc" +
        "2658cd6c960fb0c069c910a8f259593f2770984c87178c29530b6e6424b70bea" +
        "514f8568255b62ca6cc39340515ee1968aa800db4b19aa7676984b798ed5b134" +
        "116cef52b5634c7997f33c58e18d1a64499b6450f247a3555ba2a4d44782e02e" +
        "c6397c69764fd9c08f87e6b802a01bd3e77e0f544cc39944d86a5225878b435b" +
        "260bd6236f2a68ee1440ab7c06f93991c7fa6aaff20a1d862d7c73686f071cc7" +
        "e6624a5b5568e10cb3c23e6fccca3fbc63c445472a235758129fd8067b839588" +
        "a7221c250791243a8c020cccbd29425201a53bc84621412cdd0ba72ac75d2da4" +
        "a13f26a59a7629bc372e78d54776f2c781b99b9110b4833c9e69136a5098bc7f" +
        "d3a4fa9c3280557eaeeb89d0b15af4016452e42eb0d608d5850bb7491d8db6c7" +
        "03bb8d00251d69950df0e99553160122d4c5fbab7be3727f74da52ba2a240cb5" +
        "140b9704a7742d17113022b9260a15cc6a9ccbf23349ad94b57b04a29d3859ba" +
        "dcbf979515b433c86008bb43e010a2c7aff8ec7bfe508b7565b6b3898459599f" +
        "db830b7461c1c1c52b145b2829e59f09b0ca28863c70ca1d8a7aadaf6b0fdfaa" +
        "45096268505a70af267da7771555d66802405f72d190189411c5a0bbf7a7185f" +
        "857edd5a4aefc948b6b6997c3bb9ffac18153785ff752481839cb39027709a83" +
        "06538687f2501118617e5c8a67e41a2c856dbb274be4fb17ea47097f81693ed7" +
        "389b21c8eebc200f601dd2d78e89ebb919d9387768311e04c9894b08e73c4122" +
        "b41d334a56e930084645c000e21c7738765bd02fa9f6a7a3188b15739f50ab5e" +
        "f1713879d94b19964fd272a949a275e289a7c0ba9eb52558926146a280b10365" +
        "01dc76400993ba71698afc4318e38847c3f77134d7300f211862f6078bf36859" +
        "28c5a8a809a945be058b4a2e000e25e88eb7907bb7977993d9c0183248fdbb81" +
        "06ea3ade37b4b7b8a2e139c2aa19088c25227fc5bdd59826f6fa15462301eeca" +
        "0f4b76bc8992891d066b41700701b10d37899898ac9e69f7257f9330bb0770e0" +
        "621417ac392d7685c7e47497d096dd0b26161b8a41ca9d9d67664c8120de5c4e" +
        "d303c5926126b58979c3f7300ea8533ac0cbf32178a0531ca634634b46b097b3" +
        "67fb2612ea461ac8e04dcda2c5eb9543457969f9481457188a56e115dd965a81" +
        "0c3cf3217cfbbc51cc316d7799107b20256ee08ddfa87cf318a92d489c030ac5" +
        "7c25344182a5c8b770f0e4b8c03838050cc56a0b91fe84c46034c8dad78f7416" +
        "1d0e93a9b9c4cfba5384d023981ab6734977b1e0f900443b4b62f6bdf3227570" +
        "acb36b0b2e5d69cdfd9b7a05f45300e5a8918290cb0968ff1363c6048fdcb53f" +
        "63207bc841bc3c900074e48ab4c73c38662f66c9996b3a926de61a0b784e2a39" +
        "2e93db87ea841a190a6002c9b4bf237003e79961c07f156b606ac861ece75f44" +
        "ac60717871fb3b0cc2d9c987aa768eac3497b9893eb809ea4a8b24b144c2bb01" +
        "4a8a7d51d94fa5a05bef7c47459260d2ccb035806f286793343acbcfd207fd08" +
        "6b00cd517979abba9159c889bc6191290beb2aa793ba19da9ddd6275b430182e" +
        "ac87c5b27115029a696cae0afa5c38aa506f486ff52b6a9eac1414516f7fc342" +
        "55633b1abb7252218a67c213966ba6fb237a0a43b59e45c0a34902494359b193" +
        "04d9f04cd432715a17c70432680de20fbc1bcbdddc3c24037573d9a22fdb34f9" +
        "87c610a9799861369288405a138cd4850b14393a6b6344fcc38cbf07875f37a3" +
        "ca04da17cf188e017e8cee406db439078d7b0e5170aa973c154d3ef4a59628ed" +
        "3739622864bd402c715eb878247bcaf1f1070aa50599421d778cce8ffe07bdee" +
        "87dd36086fb6fcd1edb33aa50ea330f9abd98f1d6117191bb3caacb0e3f2c139"
    )
    val c = hex(
      "997f33a26049e8467f96e36b0f30a68ba7b99cb86a65dec373dc53388ffcd140" +
        "bddb7f966064c3f95766ebb90482089a136ebbc5727b8cfea68f1a5119817735" +
        "eb71eee31444fdb38f70b67b9560d8ef6d807e3339b1c824047233ad57d8d4ad" +
        "cf2097b017487bfabc85f6d23c6449cd2d0a8dab7aee9bfffc5a2a1fcfecb289" +
        "d1940a11bf1573945971d2e80d117b00ea95aa06be7e7a91dec35b291f971e79" +
        "0b4bff8a07d6099e40232746e550470a64205de84911c1e8eb88dceb615b4379" +
        "2d040031c38d1bfe55108b18e64706fd7e26384e31970655e033c26d7c27595d" +
        "cdb469a95f5a19727b38d150cd8538b5ccc14936e49a0d92692273c3ca9ebfb2" +
        "ac760a77b527e3e2b537d50900819f5d1274d4f4952f1c776f0ba4e01df91de2" +
        "d51afd4e2fe9b98208b60313961140188ec6f9ab0e8b346cb3306a2bff373495" +
        "8163a66663b93b7f5a0e3863c37b3d2803b7c29ea6ec49dacfe6ddc589ea41c4" +
        "d0543c8a8e05092b0eb2956d974042b0cb522da76f8f611bf9fc956917922c01" +
        "0d7ddb50563abc7479f05e7d80b583a3335afbe569f6f3d5683eb131c6b3f2a0" +
        "b5284ebe03eea6cc7c3435ee7b47b1680122a562428c936ddd90aad907989a4b" +
        "d26730f444900a48889582eaf39897fe19d3cac3b08d28b0e663b7cf2c30c6cf" +
        "d6b73dc227e6267503cf8ec2def07af399fa171e31248f23b8ddf33ba95c463d" +
        "f012e20170204ed8c3a6bdfafbe82a398fa5ee2e61fac25a0107614d7545421a" +
        "4ea899f0dbd2a1c34517004764c15ecb0a8bf41dad12b5b555ed4a29d4240d60" +
        "60ea3f9cbc08991f140a7ccd886b2b6a4ee6a0f87afaa9169aad9f354851e751" +
        "3ef9c85c109d617563f42057866b9cbcfba2733ab06fbdca8d4350f8afac77bc" +
        "28758ce2435196a281f13096235077ae75ac0ecb09dd123469b645796a8153c1" +
        "58934bec4c7b40174a002b6993fdbc39f187e69e465cf773515beadda077b132" +
        "71d24d8c2e05f02fc8dda19f7ab0ad5d8deb5f4aa124e3ef5288e4c8c46027ab" +
        "067b94e130c41460b68be068c6be2c62a3772e23cd13cdfa36d01b21b62b166c" +
        "0955c728c234970731d73c1bbc1967178ee146803e81772549377872cc46ebe0" +
        "17ecf40955dfe47a98f6a2b85e51a9e8f9070d844e24c3f4bbfc11392c87dacf" +
        "1f963ca1c91fea33abfc662fdb709b7adaf81ac17740bbb2699a40d1d162ff55" +
        "f277b7a9a3be7e8081a203f4c08284c8637994b0692b66cca611177bc2fb9850" +
        "a367dad0b7abab85c88880947bad9c02d54ea60ec0d9c7c36ce1a62c3cc7fa15" +
        "bf22ce2b292886485e496af718aff7a8c64915d9267d3ab89d47317fad00dcb2" +
        "bfb4953cf90a3cb849d87eb4ff67f1850684e2fd2ad26bb6681c50ce8b9817cf" +
        "e1c1e4f30e07adc3022020361b1bad3c98a49fe3d0d75a2a7dab6e3e665a3e80" +
        "1f6f124a00818dfabe19a22cc684c5bdfb94af3823294367f95c9ce3d8accc91" +
        "faebddd096adc90543744ba5fc61bf166b8e9ac1dc03fda0ce29755b17ddef3c"
    )
    val k = hex(
      "96980f7c1b160a45a8f56fb38d38d7faec7844ddf617fa47522ca2998605a71c"
    )
    assert(dk.length == SecretKeyBytes)
    assert(c.length == CiphertextBytes)
    assert(k.length == SharedSecretBytes)
    assert(
      Kem.decaps(c, dk).sameElements(k),
      "JS-noble ML-KEM-768 decaps of the ACVP tcId=89 vector must reproduce the JVM/liboqs shared secret k"
    )

  test(
    "ML-KEM-768 round-trip: keypair -> encaps -> decaps reproduces the shared secret, FIPS 203 sizes"
  ):
    val (pk, sk) = Kem.keypair()
    assert(pk.length == PublicKeyBytes)
    assert(sk.length == SecretKeyBytes)
    val (ct, ss) = Kem.encaps(pk)
    assert(ct.length == CiphertextBytes)
    assert(ss.length == SharedSecretBytes)
    assert(
      Kem.decaps(ct, sk).sameElements(ss),
      "decaps must reproduce the encapsulated shared secret"
    )

  test("ML-KEM-768 implicit rejection: a tampered ciphertext does NOT reproduce the shared secret"):
    val (pk, sk) = Kem.keypair()
    val (ct, ss) = Kem.encaps(pk)
    val tampered = ct.clone()
    tampered(0) = (tampered(0) ^ 0x01).toByte
    // FIPS 203 IND-CCA2 implicit rejection: decaps yields a pseudo-random secret, not the original.
    assert(
      !Kem.decaps(tampered, sk).sameElements(ss),
      "tampered ciphertext must not reproduce the shared secret (implicit rejection)"
    )
