package provider

import engine.{DelegationBundle, RoundOps}

/** What a device needs from its service provider (`design/offline-delegation.md` §3) — the seam
  * [[ProviderSession]] drives. Implemented in-process by [[Provider]] and over the network by
  * `transport.GrpcProviderClient` (contract `provider.proto`), so the same device-side code runs
  * against either. The round clock (`openRound` / `closeRound`) is NOT here: it belongs to the
  * provider's side, never to a device. */
trait ProviderApi:
  /** Register `user` with its notify `clientLabel` before any other call. */
  def register(user: String, clientLabel: Array[Byte]): Either[String, Unit]

  /** Replace `user`'s standing bundle, atomically. */
  def uploadBundle(user: String, bundle: DelegationBundle): Either[String, Unit]

  /** The phase-A digest for `user` in `roundId`, while that round is open. */
  def digestFor(user: String, roundId: Long): Option[Array[Byte]]

  /** Hand in the live operations for the open round; `false` = refused (e.g. past the cutoff). */
  def submitLive(user: String, ops: RoundOps): Boolean

  /** The kept receipt for `user`'s round `roundId`, removed on delivery. */
  def collectReceipt(user: String, roundId: Long): Option[StoredReceipt]

  /** Every receipt kept for `user` (rounds its bundle ran while it was away), oldest first. */
  def collectAll(user: String): Vector[StoredReceipt]
