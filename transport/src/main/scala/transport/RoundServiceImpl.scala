package transport

import metadatamessenger.messaging.v1.messaging.*
import metadatamessenger.messaging.v1.messaging.RoundServiceGrpc.RoundService
import store.ObliviousStore
import frame.Frame
import privacy.Privacy
import com.google.protobuf.ByteString
import scala.concurrent.{ExecutionContext, Future}

/** gRPC `RoundService` over an `ObliviousStore` (T020/T035, contract `messaging.proto`).
  *
  *   - `sendFrame` writes a frame iff it carries a write token. The server is BLIND to the client's
  *     `is_carrier` flag (the proto marks it "never trusted") — behaving differently on a
  *     client-supplied flag would leak real-vs-carrier to a server observer. A real frame carries a
  *     write token; a carrier carries none, so token presence alone drops carriers (FR-012).
  *   - `retrieve` reads each single-use retrieval token and pads misses with a carrier zero-frame,
  *     so the response count matches the request and reveals nothing about hits vs. misses. */
final class RoundServiceImpl(store: ObliviousStore)(using ec: ExecutionContext)
    extends RoundService:
  // Surface the backend's privacy status (Constitution IV — labeling rule).
  System.err.println(
    s"[transport] RoundService bound to store: ${
        if store.metadataPrivate then "metadata-private" else Privacy.DevLabel
      }"
  )

  def sendFrame(req: SendFrameRequest): Future[SendFrameResponse] = Future {
    if !req.writeToken.isEmpty then
      // dev: a duplicate write token (Left) is ignored rather than surfaced (no secret-dependent
      // error); the store enforces non-recurrence. `is_carrier` is intentionally not consulted.
      store.write(req.writeToken.toByteArray, req.frame.toByteArray): Unit
    SendFrameResponse(roundId = req.roundId)
  }

  def retrieve(req: RetrieveRequest): Future[RetrieveResponse] = Future {
    val frames = req.retrievalTokens.map { tok =>
      val f = store.read(tok.toByteArray).toOption.flatten.getOrElse(Frame.carrier())
      ByteString.copyFrom(f)
    }
    RetrieveResponse(roundId = req.roundId, sealedFrames = frames)
  }
