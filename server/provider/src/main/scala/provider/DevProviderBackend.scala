package provider

import engine.RoundTransport
import ping.DevNotificationServer
import store.dev.DevObliviousStore

/** The dev backend a [[Provider]] talks to: the dev PONG store and the dev PING notification
  * server, behind the engine's own [[RoundTransport]] seam — the same four operations a device's
  * transport performs. Labeled DEV (the default `privacyStatus`): neither component has
  * access-pattern privacy, and the dev notify server seals with a key it holds itself. */
final class DevProviderBackend(
    store: DevObliviousStore = DevObliviousStore(),
    notifications: DevNotificationServer
) extends RoundTransport:
  def submit(token: Array[Byte], frame: Array[Byte]): Boolean = store.write(token, frame).isRight
  def retrieve(token: Array[Byte]): Option[Array[Byte]] = store.read(token).toOption.flatten
  override def signal(roundId: Long, label: Array[Byte], bit: Int): Unit =
    notifications.signal(roundId, notifications.issueToken(roundId, bit, label)): Unit
  def fetchDigest(roundId: Long, clientLabel: Array[Byte]): Array[Byte] =
    notifications.digestAndReset(roundId, clientLabel).bytes
