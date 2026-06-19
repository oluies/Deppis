package transport

import metadatamessenger.messaging.v1.messaging.*
import metadatamessenger.messaging.v1.messaging.RoundServiceGrpc.RoundService
import store.ObliviousStore
import frame.Frame
import com.google.protobuf.ByteString
import scala.concurrent.{ExecutionContext, Future}

/** gRPC `RoundService` over an `ObliviousStore` (T020/T035, contract `messaging.proto`).
  *
  *   - `sendFrame` writes a real frame under its write token; a carrier frame (flagged, or with no
  *     write token) is dropped server-side — the client still sends exactly one frame per round so
  *     the on-wire shape is uniform (FR-012).
  *   - `retrieve` reads each single-use retrieval token and pads misses with a carrier zero-frame,
  *     so the response count matches the request and reveals nothing about hits vs. misses. */
final class RoundServiceImpl(store: ObliviousStore)(using ec: ExecutionContext) extends RoundService:

  def sendFrame(req: SendFrameRequest): Future[SendFrameResponse] = Future {
    if !req.isCarrier && !req.writeToken.isEmpty then
      // dev: a duplicate write token (Left) is ignored rather than surfaced (no secret-dependent
      // error); the store enforces non-recurrence.
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
