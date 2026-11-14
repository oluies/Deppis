package delegation

import engine.{DelegationBundle, RoundOps, RoundReceipt}

import scala.concurrent.Future

/** A device's asynchronous route to its service provider (`design/offline-delegation.md` §3) — the
  * one seam [[DeviceSession]] drives. Asynchronous so the SAME session code runs over a browser's
  * gRPC-web calls (Scala.js, Promises) and over the JVM's in-process or gRPC provider. Each method
  * is one call of the `provider.proto` contract; the provider's round clock is not here, because it
  * belongs to the provider, never to a device. */
trait ProviderPort:
  /** Register `user` with its notify `clientLabel`. */
  def register(user: String, clientLabel: Array[Byte]): Future[Either[String, Unit]]

  /** Replace `user`'s standing bundle. */
  def uploadBundle(user: String, bundle: DelegationBundle): Future[Either[String, Unit]]

  /** The phase-A digest for `user` in `roundId`, while that round is open; `None` otherwise. */
  def digestFor(user: String, roundId: Long): Future[Option[Array[Byte]]]

  /** Hand in the live operations for the open round; `false` = refused. */
  def submitLive(user: String, ops: RoundOps): Future[Boolean]

  /** The kept receipt for `user`'s round `roundId`, removed on delivery. */
  def collectReceipt(user: String, roundId: Long): Future[Option[RoundReceipt]]

  /** Drop everything kept for `user` while it was away; returns how many receipts that was. */
  def collectAll(user: String): Future[Int]
