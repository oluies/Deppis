package device

/** Device Online/Offline presence with missed-round catch-up (T039; US4).
  *
  *   - A device is `Online` or `Offline`. Round ids are plain `Long`s (cf. `Schedule.RoundPlan`),
  *     monotonically increasing; the device tracks the last round it has seen (`lastSeen`).
  *   - Going `Offline` at round R and back `Online` at round R' means rounds `(R, R']` elapsed
  *     while the device was away and must be replayed on reconnect. The endpoints are exclusive
  *     of `lastSeen` (already seen) and inclusive of the reconnect round (newly current).
  *   - Catch-up is bounded by a retention window (`Device.Retention`): a device offline for longer
  *     than the window only replays the most recent `Retention` rounds, because older rounds are no
  *     longer retained by the network. This keeps an arbitrarily-long offline period from replaying
  *     unbounded history. The window size is a protocol constant, not a clock value.
  *
  * Pure and immutable: every transition returns a new `Device`; no IO, no time/clock, no mutation.
  * Platform-neutral (compiles on JVM and Scala.js): only `scala.*` / plain `Long`. */
enum Presence:
  case Online, Offline

/** A range of rounds the device must replay on reconnect. Empty when nothing was missed.
  *
  * `from` and `to` are both inclusive round ids; for a non-empty range `from <= to` and `count`
  * (derived) is the number of rounds missed. `bounded` is true when the retention window clipped
  * the lower end (older rounds were dropped and cannot be caught up). The empty range is
  * represented by `from > to` (`Catchup.none`) and has `count == 0`; test `isEmpty` (or `count`)
  * before iterating, never `from..to` directly. */
final case class Catchup(from: Long, to: Long, bounded: Boolean):
  /** Rounds missed — derived from the range width (no stored field to drift out of sync). */
  def count: Long = if from > to then 0L else to - from + 1L
  def isEmpty: Boolean = from > to

object Catchup:
  /** The empty range (`from > to`), returned when no whole round elapsed while offline. */
  val none: Catchup = Catchup(1L, 0L, bounded = false)

/** Immutable device presence state.
  *
  *   - `presence`: whether the device is currently reachable.
  *   - `lastSeen`: the highest round the device has observed (and caught up through).
  *   - `offlineSince`: the round at which the device went offline, set only while `Offline`. */
final class Device private (
    val presence: Presence,
    val lastSeen: Long,
    private val offlineSince: Option[Long]
):
  def isOnline: Boolean = presence == Presence.Online
  def isOffline: Boolean = presence == Presence.Offline

  /** Go offline as of round `round`. Pass the **last round actually observed while online** —
    * typically `lastSeen` (keep it live with `advance` while online). `round` must be `>= lastSeen`;
    * any rounds in `(lastSeen, round)` are recorded as SEEN (they will NOT be replayed on
    * reconnect), so passing the current round rather than the last-observed one silently drops that
    * gap from catch-up. Going offline again while already offline is rejected. */
  def goOffline(round: Long): Either[String, Device] =
    if presence == Presence.Offline then Left("already offline")
    else if round < lastSeen then Left("round precedes last seen")
    else Right(new Device(Presence.Offline, round, Some(round)))

  /** Reconnect at round `currentRound`, computing the rounds to replay. `currentRound` must be
    * at least `lastSeen`. Returns the new (online) device and the bounded `Catchup` range.
    * Going online while already online is rejected (use `advance` to move a live device). */
  def goOnline(currentRound: Long): Either[String, (Device, Catchup)] =
    if presence == Presence.Online then Left("already online")
    else if currentRound < lastSeen then Left("round precedes last seen")
    else
      Right((new Device(Presence.Online, currentRound, None), missedRange(lastSeen, currentRound)))

  /** Advance an already-online device to a later round (it sees each round live, so there is
    * nothing to catch up). Rejected when offline or when the round moves backwards. */
  def advance(currentRound: Long): Either[String, Device] =
    if presence == Presence.Offline then Left("device is offline")
    else if currentRound < lastSeen then Left("round precedes last seen")
    else Right(new Device(Presence.Online, currentRound, None))

  override def equals(that: Any): Boolean = that match
    case d: Device =>
      presence == d.presence && lastSeen == d.lastSeen && offlineSince == d.offlineSince
    case _ => false

  override def hashCode: Int = (presence, lastSeen, offlineSince).hashCode

  override def toString: String =
    s"Device($presence, lastSeen=$lastSeen, offlineSince=$offlineSince)"

object Device:
  /** How many rounds back the network retains for offline catch-up. A device offline across more
    * than this many rounds replays only the most recent `Retention` of them. */
  val Retention: Long = 10_000L

  /** A fresh device, online and having seen no rounds beyond `startRound` (default 0). */
  def online(startRound: Long = 0L): Device =
    new Device(Presence.Online, startRound, None)

  /** A device known to be offline as of `since`, with `lastSeen == since`. */
  def offline(since: Long): Device =
    new Device(Presence.Offline, since, Some(since))

/** The retention-bounded set of rounds `(lastSeen, currentRound]` to replay. Empty when no whole
  * round elapsed. When the gap exceeds `Device.Retention`, the lower end is clipped to the most
  * recent `Retention` rounds and `bounded` is set. */
private def missedRange(lastSeen: Long, currentRound: Long): Catchup =
  if currentRound <= lastSeen then Catchup.none
  else
    val firstMissed = lastSeen + 1L
    val clamped = currentRound - Device.Retention + 1L
    if clamped > firstMissed then Catchup(clamped, currentRound, bounded = true)
    else Catchup(firstMissed, currentRound, bounded = false)
