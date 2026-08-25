package engine

import scala.collection.mutable

/** SINGLE-SOURCED test scaffolding for the PQ pairing-prekey specs — the platform-neutral in-memory
  * backend + conversation driver + hex helpers used by both `PqPairingSpec` (JVM, `shared/src/test`)
  * and `PqPairingJsSpec` (JS, `js/src/test`). Following the pattern PR #77 established for
  * `kem.HybridKemCrossSpec`, this ONE copy lives in `crosstest/src/test/scala`, which is wired into
  * BOTH the JVM `protocolCore` and the Scala.js `protocolCoreJS` `Test / unmanagedSourceDirectories`
  * (see build.sbt), so the helper is compiled once per platform from a single source with zero
  * lockstep-drift hazard. It touches only the platform-neutral engine API, so it compiles unchanged on
  * either build. */
object PqTestKit:
  def hex(b: Array[Byte]): String = b.map(x => f"${x & 0xff}%02x").mkString
  def unhex(s: String): Array[Byte] =
    s.filterNot(_.isWhitespace).grouped(2).map(Integer.parseInt(_, 16).toByte).toArray

  /** A shared in-memory backend modelling obsd (same shape as RoundTransportSpec's): one token→frame
    * store + a notify aggregator connecting `signal`→`fetchDigest` per (round, label tag), so two
    * engines wired to it drive the full stop-and-wait ARQ flow automatically. */
  final class FakeBackend:
    val store = mutable.Map.empty[String, Array[Byte]]

    /** EVERY store write, in order — what the untrusted store would actually observe. Lets a test
      * MEASURE the on-wire frames (e.g. that a rekey's chunk frames are the same 256 bytes as
      * content and cover frames, FR-012 / design §5) rather than assert it from the code. */
    val writes = mutable.ArrayBuffer.empty[Array[Byte]]
    private val bits = mutable.Map.empty[(Long, Vector[Byte]), mutable.Set[Int]]
    def transport(): RoundTransport = new RoundTransport:
      def submit(token: Array[Byte], frame: Array[Byte]): Boolean =
        store(hex(token)) = frame; writes += frame; true
      def retrieve(token: Array[Byte]): Option[Array[Byte]] = store.remove(hex(token))
      override def signal(roundId: Long, label: Array[Byte], bit: Int): Unit =
        bits.getOrElseUpdate((roundId, label.toVector), mutable.Set.empty) += bit
      def fetchDigest(roundId: Long, clientLabel: Array[Byte]): Array[Byte] =
        val out = new Array[Byte](64)
        bits
          .get((roundId, clientLabel.toVector))
          .foreach(_.foreach(b => out(b >> 3) = (out(b >> 3) | (1 << (b & 7))).toByte))
        out

  /** A network that EATS LIVE FRAMES, and counts the byte-identical re-presentations that ARQ makes
    * in response. Single-sourced here because both the example-based `PqRekeyCrossSpec` and the
    * property-based `PqRekeyModelSpec` need exactly this adversary and must not drift apart.
    *
    * ==Loss: swallow a live `retrieve`, never a store entry==
    * A drop is a `retrieve` that WOULD have returned a frame, suppressed after the store already
    * consumed it — so it is gone for good and ARQ must recover it. `lost` therefore counts LIVE
    * FRAMES SWALLOWED (content, control, or ack-only), each one a real frame the peer wrote.
    *
    * The obvious alternative — reach into `FakeBackend.store` and `remove` a key — is a TRAP that an
    * earlier revision of BOTH specs fell into. The store is append-only apart from
    * successfully-retrieved directional tokens: cover writes go under a `coverKey`-derived token
    * that is NEVER retrieved, so they pile up forever. Measured on a warmed pair over 700 rounds, an
    * idle pair leaves ~1,200 dead cover entries against ~1 live frame, so a `remove` almost always
    * deleted garbage and `assert(dropped > 0)` could not tell the difference — it counted map
    * removals, not lost deliveries.
    *
    * `lost` is still NOT a "deliveries prevented" count: the swallowed frame may be an ack, or a
    * cached content retransmit the ratchet would have refused anyway. Stating it more strongly would
    * overclaim by exactly the margin that made the `store.remove` metric untrustworthy.
    *
    * ==Duplication: measured, not injected==
    * `repeats` counts retrieves that returned bytes this transport had already returned before. Such
    * duplicates are UBIQUITOUS BY CONSTRUCTION and prove nothing on their own: stop-and-wait
    * re-presents the unacked head under every round's token until the ack lands, so the cached wire
    * (`Engine.rt.headWire`) is delivered byte-identically several times even on a perfectly clean
    * network. The counter exists to show the duplicate-handling path is genuinely exercised — the
    * ratchet's cached-retransmit `None` and ARQ's `isNewMessage` sequence dedup — and a test must
    * earn the "duplicates" half of its name from an EXACTLY-ONCE DELIVERY assertion, not from
    * `repeats > 0`.
    *
    * The adversary may not forge or reorder: every frame is AEAD-sealed under keys the network does
    * not hold (a tampered frame is just a dropped one), and round-derived addressing plus
    * stop-and-wait mean an in-flight frame cannot be overtaken. Forged envelopes are exercised where
    * they ARE reachable — a malicious PEER — in `PqRekeyCrossSpec`. */
  final class UnreliableTransport(inner: RoundTransport, rng: scala.util.Random)
      extends RoundTransport:

    /** Swallow one live frame in `dropOneIn` (0 = a clean network). */
    var dropOneIn: Int = 0

    /** Live frames swallowed — see the class doc for what this does and does not mean. */
    var lost: Int = 0

    /** Retrieves that returned a frame (post-drop). */
    var delivered: Int = 0

    /** Retrieves that returned bytes already returned earlier — ARQ re-presentation, not an attack. */
    var repeats: Int = 0

    private val seenFrames = mutable.Set.empty[String]

    def submit(token: Array[Byte], frame: Array[Byte]): Boolean = inner.submit(token, frame)

    def retrieve(token: Array[Byte]): Option[Array[Byte]] =
      inner.retrieve(token) match
        case Some(_) if dropOneIn > 0 && rng.nextInt(dropOneIn) == 0 =>
          lost += 1
          None
        case Some(f) =>
          delivered += 1
          if !seenFrames.add(hex(f)) then repeats += 1
          Some(f)
        case None => None

    override def signal(roundId: Long, label: Array[Byte], bit: Int): Unit =
      inner.signal(roundId, label, bit)

    def fetchDigest(roundId: Long, clientLabel: Array[Byte]): Array[Byte] =
      inner.fetchDigest(roundId, clientLabel)

    override def privacyStatus: privacy.Privacy.BuildPrivacyStatus = inner.privacyStatus

  /** Tick both engines through rounds `from..to`, collecting each side's delivered plaintexts. */
  def converse(a: Engine, b: Engine, from: Long, to: Long): (Seq[String], Seq[String]) =
    val ma = mutable.ArrayBuffer.empty[String]; val mb = mutable.ArrayBuffer.empty[String]
    for r <- from to to do
      a.tick(r); b.tick(r)
      ma ++= a.drainEvents().collect { case EngineEvent.MessageReceived(_, t, _) => t }
      mb ++= b.drainEvents().collect { case EngineEvent.MessageReceived(_, t, _) => t }
    (ma.toSeq, mb.toSeq)
