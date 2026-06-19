package schedule

import frame.Frame

/** Client round schedule (T015, FR-012). INVARIANT: every round emits exactly one 256-byte
  * frame and one retrieval, regardless of whether a real message is queued — a carrier frame
  * fills the gap so the traffic shape is independent of real-message presence. The hidden
  * `kind` (Real vs Carrier) is never exposed on the wire. */
object Schedule:
  enum FrameKind:
    case Real, Carrier

  final case class RoundPlan(roundId: Long, kind: FrameKind, frame: Array[Byte], retrieve: Boolean):
    require(frame.length == Frame.Size, "round must emit a fixed-size frame")

  /** Plan one round. `realPayload` is `Some` iff a real message is queued; both branches
    * return a shape-identical plan (one 256-byte send + one retrieve). */
  def planRound(roundId: Long, realPayload: Option[Array[Byte]]): Either[String, RoundPlan] =
    realPayload match
      case Some(p) => Frame.pad(p).map(f => RoundPlan(roundId, FrameKind.Real, f, retrieve = true))
      case None    => Right(RoundPlan(roundId, FrameKind.Carrier, Frame.carrier(), retrieve = true))
