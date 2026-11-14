package delegation

import engine.{DelegationBundle, NotifyDigest, PqTestKit, RoundOps, RoundReceipt}

import scala.collection.mutable
import scala.concurrent.Future

/** A minimal in-memory provider for the cross-platform delegation tests. The real `provider.Provider`
  * is JVM-only (server module); the JVM suites run it — in process, over gRPC and over the Rust
  * `obsd` — through this same shared [[DeviceSession]]. This double only has to stand in where the
  * real one cannot run (Scala.js), so it implements just the round semantics a device relies on:
  * phase-A digest fetch, one live set per user before the cutoff, live-else-slot at the cutoff, and
  * receipts removed on delivery. Every answer is an already-completed Future. */
final class FakeProvider extends ProviderPort:
  val backend = PqTestKit.FakeBackend()
  private val net = backend.transport()
  private val labels = mutable.LinkedHashMap.empty[String, Array[Byte]]
  private val bundles = mutable.Map.empty[String, mutable.Map[Long, RoundOps]]
  private var open: Option[Long] = None
  private val digests = mutable.Map.empty[String, Array[Byte]]
  private val live = mutable.Map.empty[String, RoundOps]
  private val receipts = mutable.Map.empty[(String, Long), RoundReceipt]
  var writes = 0

  def register(user: String, clientLabel: Array[Byte]) =
    labels(user) = clientLabel.clone()
    Future.successful(Right(()))
  def uploadBundle(user: String, bundle: DelegationBundle) =
    bundles(user) = mutable.Map.from(bundle.slots.map(s => s.roundId -> s))
    Future.successful(Right(()))
  def digestFor(user: String, roundId: Long) =
    Future.successful(if open.contains(roundId) then digests.get(user) else None)
  def submitLive(user: String, ops: RoundOps) =
    val ok = open.contains(ops.roundId) && labels.contains(user) && !live.contains(user)
    if ok then live(user) = ops
    Future.successful(ok)
  def collectReceipt(user: String, roundId: Long) =
    Future.successful(receipts.remove((user, roundId)))
  def collectAll(user: String) =
    val mine = receipts.keys.filter(_._1 == user).toVector
    mine.foreach(receipts.remove)
    Future.successful(mine.size)

  def openRound(r: Long): Unit =
    open = Some(r)
    live.clear()
    for (u, l) <- labels do digests(u) = net.fetchDigest(r - 1, NotifyDigest.labelTag(l))

  def closeRound(r: Long): Unit =
    for u <- labels.keys do
      val liveOps = live.get(u)
      val slot = bundles.get(u).flatMap(_.remove(r))
      liveOps.orElse(slot).foreach { ops =>
        val accepted = net.submit(ops.writeToken, ops.frame)
        writes += 1
        val sig = if accepted then ops.signal else ops.fallbackSignal
        net.signal(r, sig.label, sig.bit)
        receipts((u, r)) = RoundReceipt(r, liveOps.isDefined, accepted, net.retrieve(ops.readToken))
      }
      bundles.get(u).foreach(b => b.keys.filter(_ <= r).toVector.foreach(b.remove))
    open = None
