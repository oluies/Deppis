package engine

import kem.HybridKem
import org.scalatest.funsuite.AnyFunSuite
import scala.collection.mutable

/** Runs under Node (Scala.js): proves the GENERATED JS engine path performs the full post-quantum
  * pairing prekey (US7) — the initiator generates a hybrid-KEM keypair (X25519 via @noble/curves +
  * ML-KEM-768 via @noble/post-quantum), the responder encapsulates, the initiator decapsulates, and
  * both seed a byte-identical PQ content root so a message actually round-trips through the JS ratchet.
  * The JS `kem.HybridKem` interoperates with the JVM one (KAT-pinned in HybridKemSpec/HybridKemJsSpec);
  * here we prove the JS↔JS engine flow end to end.
  *
  * HONEST LABELING (Constitution IV): this hardens only the pairing SEED; the ongoing per-message
  * X25519 DH ratchet stays classical. */
class PqPairingJsSpec extends AnyFunSuite:

  private def secret(s: String): Array[Byte] = s.getBytes("UTF-8")
  private def hex(b: Array[Byte]): String = b.map(x => f"${x & 0xff}%02x").mkString

  private final class FakeBackend:
    val store = mutable.Map.empty[String, Array[Byte]]
    private val bits = mutable.Map.empty[(Long, Vector[Byte]), mutable.Set[Int]]
    def transport(): RoundTransport = new RoundTransport:
      def submit(token: Array[Byte], frame: Array[Byte]): Boolean = {
        store(hex(token)) = frame; true
      }
      def retrieve(token: Array[Byte]): Option[Array[Byte]] = store.remove(hex(token))
      override def signal(roundId: Long, label: Array[Byte], bit: Int): Unit =
        bits.getOrElseUpdate((roundId, label.toVector), mutable.Set.empty) += bit
      def fetchDigest(roundId: Long, clientLabel: Array[Byte]): Array[Byte] =
        val out = new Array[Byte](64)
        bits
          .get((roundId, clientLabel.toVector))
          .foreach(_.foreach(b => out(b >> 3) = (out(b >> 3) | (1 << (b & 7))).toByte))
        out

  private def converse(a: Engine, b: Engine, from: Long, to: Long): (Seq[String], Seq[String]) =
    val ma = mutable.ArrayBuffer.empty[String]; val mb = mutable.ArrayBuffer.empty[String]
    for r <- from to to do
      a.tick(r); b.tick(r)
      ma ++= a.drainEvents().collect { case EngineEvent.MessageReceived(_, t, _) => t }
      mb ++= b.drainEvents().collect { case EngineEvent.MessageReceived(_, t, _) => t }
    (ma.toSeq, mb.toSeq)

  test("JS PQ pairing: initiator+responder run the KEM exchange and exchange a message"):
    val be = FakeBackend()
    val aLabel = "alice".getBytes; val bLabel = "bob".getBytes
    val alice = new Engine(Some(be.transport()), clientLabel = aLabel)
    val bob = new Engine(Some(be.transport()), clientLabel = bLabel)
    val aRes = alice
      .addBuddy(
        secret("oob"),
        BuddyRole.Initiator,
        peerNotifyLabel = bLabel,
        initiatePqPrekey = true
      )
      .toOption
      .get
    assert(aRes.kemPublicKey.get.length == HybridKem.PublicKeyBytes)
    val bRes = bob
      .addBuddy(
        secret("oob"),
        BuddyRole.Responder,
        peerNotifyLabel = aLabel,
        initiatorKemPublicKey = aRes.kemPublicKey
      )
      .toOption
      .get
    assert(bRes.kemCiphertext.get.length == HybridKem.CiphertextBytes)
    assert(aRes.pairId == bRes.pairId, "pairId unchanged by the KEM (symmetric OOB derivation)")
    assert(
      alice.confirmBuddy(aRes.pairId, matched = true, kemCiphertext = bRes.kemCiphertext).isRight
    )
    assert(bob.confirmBuddy(bRes.pairId, matched = true).isRight)
    alice.drainEvents(); bob.drainEvents()
    // A delivered message proves both JS ratchets seeded a byte-identical PQ content root.
    assert(alice.sendMessage(aRes.pairId, "js pq hello") == Right(1))
    val (_, bobMsgs) = converse(alice, bob, 1, 12)
    assert(bobMsgs == Seq("js pq hello"), s"bob got $bobMsgs")

  test("JS PQ seed check: encaps/decaps agree and change the content root"):
    val base = KeySchedule.contentRoot(handshake.Handshake.init(secret("oob")).pairKey)
    val (pub, sec) = HybridKem.keypair()
    val (ct, ssEnc) = HybridKem.encaps(pub)
    val ssDec = HybridKem.decaps(ct, sec)
    assert(ssEnc.sameElements(ssDec))
    assert(
      KeySchedule.pqContentRoot(base, ssEnc).sameElements(KeySchedule.pqContentRoot(base, ssDec))
    )
    assert(!KeySchedule.pqContentRoot(base, ssEnc).sameElements(base))

  test("JS fail-closed: a matched PQ pairing without the ciphertext is refused"):
    val alice = new Engine()
    val res =
      alice.addBuddy(secret("oob"), BuddyRole.Initiator, initiatePqPrekey = true).toOption.get
    assert(
      alice
        .confirmBuddy(res.pairId, matched = true)
        .left
        .toOption
        .map(_.code)
        .contains("pq_prekey_required")
    )
    assert(alice.confirmedCount == 0)

  test("JS JSON boundary carries the base64 PQ fields end to end"):
    val ca = new EngineCodec(new Engine())
    val cb = new EngineCodec(new Engine())
    val add = ujson.read(
      ca.handle(
        """{"apiVersion":"1","command":"addBuddy","args":{"sharedSecret":"oob","role":"initiator","pqPrekey":true}}"""
      )
    )
    val pairId = add("result")("pairId").str
    val kemPub = add("result")("kemPublicKey").str
    val respAdd = ujson.read(
      cb.handle(
        s"""{"apiVersion":"1","command":"addBuddy","args":{"sharedSecret":"oob","role":"responder","initiatorKemPublicKey":"$kemPub"}}"""
      )
    )
    val ct = respAdd("result")("kemCiphertext").str
    val conf = ujson.read(
      ca.handle(
        s"""{"apiVersion":"1","command":"confirmBuddy","args":{"pairId":"$pairId","matched":true,"kemCiphertext":"$ct"}}"""
      )
    )
    assert(conf("events").arr.head("event").str == "buddyConfirmed")
