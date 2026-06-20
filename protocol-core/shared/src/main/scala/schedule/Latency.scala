package schedule

/** End-to-end latency model (SC-001). The system trades latency for metadata privacy: messages
  * move on a fixed round schedule (one send + one retrieve per round, [[Schedule]]), so delivery
  * latency is `rounds-to-deliver × round interval`, NOT network RTT.
  *
  * SC-001 requires a two-party exchange to complete in **minute-order latency (single-digit
  * rounds)**. The round interval is a tuned planning parameter (research D: ~10–30 s, chosen to
  * hold minute-order latency under uniform cover traffic). This object pins that parameter and the
  * worst-case round counts so a regression (e.g. bumping the interval out of range) is caught by a
  * test rather than discovered in the field. */
object Latency:

  /** Tuned round interval (seconds). Within research D's 10–30 s window; chosen so a single-digit
    * round exchange stays minute-order (see [[meetsSc001]]). */
  val RoundIntervalSeconds: Int = 15

  /** Worst-case rounds to deliver ONE message: the sending round plus, at worst, the receiver's
    * next retrieve (a message stored just after this round's retrieve is picked up next round).
    * The [[Schedule]] invariant "one retrieve per round" bounds this at 2. */
  val OneWayRoundsWorstCase: Int = 2

  /** Worst-case rounds for a full round trip (message + reply): two full one-way deliveries with no
    * overlap — the reply cannot piggyback on the round in which the message arrives (that round's
    * send was already emitted), so it goes out the next round, making it 2 × one-way = 4. */
  val RoundTripRoundsWorstCase: Int = 2 * OneWayRoundsWorstCase

  /** Latency (seconds) for `rounds` rounds at the tuned interval. */
  def latencySeconds(rounds: Int): Long = rounds.toLong * RoundIntervalSeconds

  /** "Single-digit rounds" per SC-001 / the dimensioning note. */
  def isSingleDigitRounds(rounds: Int): Boolean = rounds >= 1 && rounds < 10

  /** "Minute-order" — on the order of one minute. We treat ≤ 120 s (and ≥ 5 s) as minute-order;
    * this is what makes the round-interval choice a guarded invariant rather than a free knob. */
  def isMinuteOrder(seconds: Long): Boolean = seconds >= 5 && seconds <= 120

  /** SC-001: a `rounds`-round exchange at the tuned interval is single-digit AND minute-order. */
  def meetsSc001(rounds: Int): Boolean =
    isSingleDigitRounds(rounds) && isMinuteOrder(latencySeconds(rounds))
