package integration

import crypto.Crypto
import engine.{BuddyRole, Engine, EngineEvent}
import io.grpc.inprocess.{InProcessChannelBuilder, InProcessServerBuilder}
import io.grpc.{ManagedChannel, Server}
import metadatamessenger.notify.v1.{notify as npb}
import metadatamessenger.store.v1.{store as spb}
import ping.DevNotificationServer
import store.dev.DevObliviousStore
import transport.{
  EnclaveNotificationClient,
  EnclaveObliviousStore,
  GrpcRoundTransport,
  NotificationServiceImpl,
  StoreServiceImpl
}

import scala.collection.mutable
import scala.concurrent.ExecutionContext.Implicits.global

/** A real server round for integration tests: the JVM ObliviousStore and NotificationService
  * behind in-process gRPC, and client engines driving them through [[GrpcRoundTransport]] — the
  * same adapter a JVM client uses against the enclave fronts. No Rust `obsd`, so it runs in the
  * plain JVM suite. Labeled DEV (dev store, dev notify key): no metadata-privacy claim. */
final class RoundStack extends AutoCloseable:
  private val notifyKey = Array.tabulate(Crypto.KeyBytes)(i => (i * 13 + 7).toByte)
  private val sealer = DevNotificationServer(notifyKey) // DEV: the front seals in-enclave for real
  private val name = InProcessServerBuilder.generateName()
  private val server: Server = InProcessServerBuilder
    .forName(name)
    .directExecutor()
    .addService(
      spb.ObliviousStoreGrpc.bindService(StoreServiceImpl(new DevObliviousStore()), global)
    )
    .addService(
      npb.NotificationServiceGrpc.bindService(
        NotificationServiceImpl(DevNotificationServer(notifyKey)),
        global
      )
    )
    .build()
    .start()
  private val channel: ManagedChannel =
    InProcessChannelBuilder.forName(name).directExecutor().build()

  /** A client engine on this round, with notify label [[label]]. */
  final class Device(val name: String):
    val label: Array[Byte] = s"$name-label".getBytes("UTF-8")
    val engine: Engine = Engine(
      Some(
        GrpcRoundTransport(
          EnclaveObliviousStore(spb.ObliviousStoreGrpc.blockingStub(channel), attested = false),
          EnclaveNotificationClient(
            npb.NotificationServiceGrpc.blockingStub(channel),
            attested = false
          ),
          notifySealer = Some((r, b, l) => sealer.issueToken(r, b, l))
        )
      ),
      clientLabel = label
    )

    /** (pairId, plaintext, round it surfaced in) — every message this device has received. */
    val received = mutable.ArrayBuffer.empty[(String, String, Long)]
    private val pairs = mutable.Map.empty[String, String] // peer name -> pairId

    def pairId(peer: Device): String = pairs(peer.name)
    def send(peer: Device, text: String): Unit =
      engine.sendMessage(pairId(peer), text).fold(e => throw AssertionError(e.toString), _ => ())

    def tick(round: Long): Unit =
      engine.tick(round).left.foreach(e => throw AssertionError(s"$name tick $round: $e"))
      engine.drainEvents().foreach {
        case EngineEvent.MessageReceived(p, t, _) => received += ((p, t, round))
        case _ => ()
      }

    def texts: Seq[String] = received.map(_._2).toSeq
    private[RoundStack] def remember(peer: Device, pid: String): Unit = pairs(peer.name) = pid

  def device(name: String): Device = Device(name)

  /** Pair [[a]] (initiator) with [[b]] (responder) out of band, both confirmed. */
  def pair(a: Device, b: Device): Unit =
    val secret = s"oob-${a.name}-${b.name}".getBytes("UTF-8")
    val pid = a.engine
      .addBuddy(secret, BuddyRole.Initiator, peerNotifyLabel = b.label)
      .fold(e => throw AssertionError(e.toString), _.pairId)
    b.engine
      .addBuddy(secret, BuddyRole.Responder, peerNotifyLabel = a.label)
      .fold(e => throw AssertionError(e.toString), _ => ())
    a.engine.confirmBuddy(pid, matched = true).left.foreach(e => throw AssertionError(e.toString))
    b.engine.confirmBuddy(pid, matched = true).left.foreach(e => throw AssertionError(e.toString))
    a.engine.drainEvents(); b.engine.drainEvents()
    a.remember(b, pid); b.remember(a, pid)

  /** Rounds `from..to`; each round every device in [[online]] ticks (writes, signals, reads). */
  def run(online: Seq[Device], from: Long, to: Long)(until: => Boolean = false): Long =
    var r = from
    while r <= to && !until do
      online.foreach(_.tick(r))
      r += 1
    r - 1

  def close(): Unit =
    channel.shutdownNow(); server.shutdownNow(): Unit
