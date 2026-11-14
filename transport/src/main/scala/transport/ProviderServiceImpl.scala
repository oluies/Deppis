package transport

import com.google.protobuf.ByteString
import engine.DelegationBundle
import metadatamessenger.provider.v1.provider as ppb
import metadatamessenger.provider.v1.provider.ProviderServiceGrpc.ProviderService

import java.security.{MessageDigest, SecureRandom}
import scala.concurrent.{ExecutionContext, Future}

/** gRPC front of the untrusted service provider (contract `provider.proto`, T038,
  * `design/offline-delegation.md` §3): what devices talk to instead of the backend.
  *
  * The provider's round clock (`openRound` / `closeRound`) is driven on this side, by whoever owns
  * the `Provider` — never by a device. This front only relays the device-facing calls, after
  * checking the caller's session secret: a user name is registered once, gets a random secret, and
  * every later call must present it. The provider keeps only the SHA-256 of the secret, compared in
  * constant time, and with a persistent store it survives a restart. That keeps one client from
  * acting in another user's name; it is not a privacy mechanism.
  *
  * Labeled `DEV, NO METADATA PRIVACY` (Constitution IV), and says so when bound — see the contract's
  * header for why that holds until Phase 4. */
final class ProviderServiceImpl(provider: _root_.provider.Provider)(using ec: ExecutionContext)
    extends ProviderService:
  System.err.println(
    s"[transport] ProviderService bound: ${provider.label} (metadataPrivate=${provider.metadataPrivate})"
  )

  private val rng = new SecureRandom()
  private val NotAuthorised = "not authorised"

  // The provider keeps only the SHA-256 of each session secret (persisted with the registration
  // when its store is persistent, so sessions survive a restart). The secret is 32 random bytes, so
  // a plain hash is enough: there is nothing to brute-force.
  private def sha256(b: Array[Byte]): Array[Byte] = MessageDigest.getInstance("SHA-256").digest(b)

  private def authorised(user: String, session: ByteString): Boolean =
    provider.sessionHashOf(user).exists(h => MessageDigest.isEqual(h, sha256(session.toByteArray)))

  def register(req: ppb.RegisterRequest): Future[ppb.RegisterResponse] = Future {
    this.synchronized {
      if provider.isRegistered(req.user) then
        ppb.RegisterResponse(ok = false, error = "user already registered")
      else
        val secret = new Array[Byte](32)
        rng.nextBytes(secret)
        provider.register(req.user, req.clientLabel.toByteArray, Some(sha256(secret))) match
          case Left(e) => ppb.RegisterResponse(ok = false, error = e)
          case Right(()) => ppb.RegisterResponse(ok = true, session = ByteString.copyFrom(secret))
    }
  }

  def uploadBundle(req: ppb.UploadBundleRequest): Future[ppb.UploadBundleResponse] = Future {
    if !authorised(req.user, req.session) then ppb.UploadBundleResponse(ok = false, NotAuthorised)
    else
      val bundle =
        DelegationBundle(req.fromRound, req.slots.iterator.map(ProviderProto.fromProto).toVector)
      provider.uploadBundle(req.user, bundle) match
        case Left(e) => ppb.UploadBundleResponse(ok = false, error = e)
        case Right(()) => ppb.UploadBundleResponse(ok = true)
  }

  def getDigest(req: ppb.GetDigestRequest): Future[ppb.GetDigestResponse] = Future {
    val digest =
      if authorised(req.user, req.session) then provider.digestFor(req.user, req.roundId) else None
    digest.fold(ppb.GetDigestResponse(ok = false))(d =>
      ppb.GetDigestResponse(ok = true, digest = ByteString.copyFrom(d))
    )
  }

  def submitLive(req: ppb.SubmitLiveRequest): Future[ppb.SubmitLiveResponse] = Future {
    val accepted = authorised(req.user, req.session) &&
      req.ops.exists(o => provider.submitLive(req.user, ProviderProto.fromProto(o)))
    ppb.SubmitLiveResponse(accepted = accepted)
  }

  def collectReceipt(req: ppb.CollectReceiptRequest): Future[ppb.CollectReceiptResponse] = Future {
    val kept =
      if authorised(req.user, req.session) then provider.collectReceipt(req.user, req.roundId)
      else None
    kept.fold(ppb.CollectReceiptResponse(found = false))(r =>
      ppb.CollectReceiptResponse(found = true, receipt = Some(ProviderProto.toProto(r)))
    )
  }

  def collectAll(req: ppb.CollectAllRequest): Future[ppb.CollectAllResponse] = Future {
    val all =
      if authorised(req.user, req.session) then provider.collectAll(req.user) else Vector.empty
    ppb.CollectAllResponse(receipts = all.map(ProviderProto.toProto))
  }
