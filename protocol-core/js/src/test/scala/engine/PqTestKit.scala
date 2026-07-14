package engine

import scala.collection.mutable

/** JS-source mirror of `protocol-core/shared/src/test/scala/engine/PqTestKit.scala` (the JVM and JS
  * test source sets are separate — see build.sbt — so this shared PQ-pairing scaffolding is compiled
  * once per platform). Keep byte-for-byte in sync with the JVM copy. */
object PqTestKit:
  def hex(b: Array[Byte]): String = b.map(x => f"${x & 0xff}%02x").mkString
  def unhex(s: String): Array[Byte] =
    s.filterNot(_.isWhitespace).grouped(2).map(Integer.parseInt(_, 16).toByte).toArray

  final class FakeBackend:
    val store = mutable.Map.empty[String, Array[Byte]]
    private val bits = mutable.Map.empty[(Long, Vector[Byte]), mutable.Set[Int]]
    def transport(): RoundTransport = new RoundTransport:
      def submit(token: Array[Byte], frame: Array[Byte]): Boolean =
        store(hex(token)) = frame; true
      def retrieve(token: Array[Byte]): Option[Array[Byte]] = store.remove(hex(token))
      override def signal(roundId: Long, label: Array[Byte], bit: Int): Unit =
        bits.getOrElseUpdate((roundId, label.toVector), mutable.Set.empty) += bit
      def fetchDigest(roundId: Long, clientLabel: Array[Byte]): Array[Byte] =
        val out = new Array[Byte](64)
        bits
          .get((roundId, clientLabel.toVector))
          .foreach(_.foreach(b => out(b >> 3) = (out(b >> 3) | (1 << (b & 7))).toByte))
        out

  def converse(a: Engine, b: Engine, from: Long, to: Long): (Seq[String], Seq[String]) =
    val ma = mutable.ArrayBuffer.empty[String]; val mb = mutable.ArrayBuffer.empty[String]
    for r <- from to to do
      a.tick(r); b.tick(r)
      ma ++= a.drainEvents().collect { case EngineEvent.MessageReceived(_, t, _) => t }
      mb ++= b.drainEvents().collect { case EngineEvent.MessageReceived(_, t, _) => t }
    (ma.toSeq, mb.toSeq)
