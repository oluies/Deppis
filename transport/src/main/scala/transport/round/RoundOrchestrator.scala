package transport.round

import org.apache.pekko.actor.typed.{ActorRef, Behavior}
import org.apache.pekko.actor.typed.scaladsl.Behaviors

/** Pekko typed actor that owns the server's monotonic **round clock** (T020).
  *
  * The metadata-private protocol runs in discrete rounds (every client does exactly one store
  * write + one read per round — FR-012). A real batched-round server needs a single authority for
  * "which round is it now" and a place to hang per-round barrier/aggregation logic; this actor is
  * that seam. It is intentionally minimal — it advances and reports the round — so the orchestration
  * skeleton exists and is testable without prejudging the batching policy.
  *
  * Single source of truth, single-threaded by the actor contract: round ids only move forward. */
object RoundOrchestrator:
  sealed trait Command

  /** Move to the next round. */
  case object Advance extends Command

  /** Ask for the current round id. */
  final case class Current(replyTo: ActorRef[Long]) extends Command

  /** A fresh orchestrator starting at `startRound` (default 0). */
  def apply(startRound: Long = 0L): Behavior[Command] =
    Behaviors.setup { _ =>
      def active(round: Long): Behavior[Command] =
        Behaviors.receiveMessage {
          case Advance => active(round + 1L)
          case Current(replyTo) =>
            replyTo ! round
            Behaviors.same
        }
      active(startRound)
    }
