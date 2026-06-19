package transport

import metadatamessenger.notify.v1.notify.*
import metadatamessenger.notify.v1.notify.NotificationServiceGrpc.NotificationService
import ping.DevNotificationServer
import com.google.protobuf.ByteString
import scala.concurrent.{ExecutionContext, Future}

/** gRPC `NotificationService` front over a `DevNotificationServer` (T030, contract `notify.proto`).
  *
  *   - `signal` submits a sealed token and ALWAYS returns a uniform `SignalResponse`, silently
  *     dropping a forged/tampered token rather than surfacing an error. Revealing whether a token
  *     authenticated would leak validity to a submitter/observer, so the result is not exposed
  *     (the underlying AEAD rejection still prevents the bit from being set).
  *   - `fetchDigest` consumes the client's accumulated digest (`digestAndReset`), so a retrieved
  *     notification is not re-reported; an empty round returns an all-zero carrier digest. */
final class NotificationServiceImpl(ns: DevNotificationServer)(using ec: ExecutionContext) extends NotificationService:

  def signal(req: SignalRequest): Future[SignalResponse] = Future {
    ns.signal(req.sealedToken.toByteArray) // result intentionally ignored (uniform response)
    SignalResponse(roundId = req.roundId)
  }

  def fetchDigest(req: FetchDigestRequest): Future[FetchDigestResponse] = Future {
    val digest = ns.digestAndReset(req.clientLabel.toByteArray)
    FetchDigestResponse(roundId = req.roundId, digest = ByteString.copyFrom(digest.bytes))
  }
