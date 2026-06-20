package engine

import scala.scalajs.js
import scala.scalajs.js.typedarray.Uint8Array

/** The JS object the host (Flutter web) supplies to back the engine's [[RoundTransport]] (T032b).
  *
  * It is **synchronous** by contract: browser network I/O (gRPC-web / fetch) is async, but the
  * engine's `tick` is synchronous, so the host uses a *staging* model — before calling `tick` it
  * pre-fetches this round's notify digest and any retrievable frames into a local buffer, and it
  * buffers `submit`s to flush after `tick`. So:
  *   - `submit` records the frame to send and returns `true` (the host flushes it post-tick; a
  *     return of `false` tells the engine to keep the frame queued for next round);
  *   - `mailWaiting` reads the pre-fetched digest answer for this round;
  *   - `retrieve` reads a pre-fetched frame for the token, or returns `null` if none is staged.
  *
  * Bytes cross as `Uint8Array`; `roundId` crosses as a JS number (round ids are small). */
@js.native
trait JsTransport extends js.Object:
  def submit(token: Uint8Array, frame: Uint8Array): Boolean       = js.native
  def mailWaiting(roundId: Double, clientLabel: Uint8Array): Boolean = js.native
  def retrieve(token: Uint8Array): Uint8Array                     = js.native // null when none staged

/** Adapts a host-supplied [[JsTransport]] to the cross-platform [[RoundTransport]] the engine uses,
  * so the SAME `Engine.tick` notify-before-retrieval logic that runs on the JVM drives a browser
  * backend. This layer only converts byte buffers; it sees no plaintext or keys. */
object JsRoundTransport:
  /** Number.MAX_SAFE_INTEGER — the largest integer a JS number represents exactly. */
  val MaxSafeRound: Long = (1L << 53) - 1

final class JsRoundTransport(t: JsTransport) extends RoundTransport:

  def submit(token: Array[Byte], frame: Array[Byte]): Boolean =
    t.submit(Uint8.toJs(token), Uint8.toJs(frame))

  def mailWaiting(roundId: Long, clientLabel: Array[Byte]): Boolean =
    // `roundId` crosses as a JS number; reject anything that would not round-trip exactly rather
    // than silently aliasing a large round id (caught by the codec's guard → bad_request).
    require(
      roundId >= 0 && roundId <= JsRoundTransport.MaxSafeRound,
      "roundId out of JS-safe-integer range"
    )
    t.mailWaiting(roundId.toDouble, Uint8.toJs(clientLabel))

  def retrieve(token: Array[Byte]): Option[Array[Byte]] =
    Option(t.retrieve(Uint8.toJs(token))).map(Uint8.toBytes) // JS `null` → None
