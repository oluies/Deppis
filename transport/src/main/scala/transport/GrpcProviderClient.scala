package transport

import com.google.protobuf.ByteString
import engine.{DelegationBundle, RoundOps}
import metadatamessenger.provider.v1.provider as ppb

import scala.collection.concurrent.TrieMap
import scala.util.control.NonFatal

/** A device's route to its service provider over gRPC (contract `provider.proto`): the networked
  * [[_root_.provider.ProviderApi]], so `provider.ProviderSession` drives an engine through a remote
  * provider exactly as through an in-process one. With this, a device needs no store or notify
  * transport of its own — the provider is its only backend connection (§2 Option 3, §6).
  *
  * Holds the session secret `Register` returned for each user it registered. A failed call degrades
  * to the safe answer for each operation: a refused live set (the bundle slot runs instead), no
  * digest (the round reads as idle), no receipt. Every message is generic (Constitution II). */
final class GrpcProviderClient(stub: ppb.ProviderServiceGrpc.ProviderServiceBlockingStub)
    extends _root_.provider.ProviderApi:
  private val sessions = TrieMap.empty[String, ByteString]

  def register(user: String, clientLabel: Array[Byte]): Either[String, Unit] =
    try
      val r = stub.register(ppb.RegisterRequest(user, ByteString.copyFrom(clientLabel)))
      if r.ok then
        sessions(user) = r.session
        Right(())
      else Left(r.error)
    catch case NonFatal(_) => Left("provider register failed")

  private def session(user: String): Option[ByteString] = sessions.get(user)

  def uploadBundle(user: String, bundle: DelegationBundle): Either[String, Unit] =
    session(user).toRight("not registered").flatMap { s =>
      try
        val req = ppb.UploadBundleRequest(
          user,
          s,
          bundle.fromRound,
          bundle.slots.map(ProviderProto.toProto)
        )
        val r = stub.uploadBundle(req)
        if r.ok then Right(()) else Left(r.error)
      catch case NonFatal(_) => Left("provider upload failed")
    }

  def digestFor(user: String, roundId: Long): Option[Array[Byte]] =
    session(user).flatMap { s =>
      try
        val r = stub.getDigest(ppb.GetDigestRequest(user, s, roundId))
        Option.when(r.ok)(r.digest.toByteArray)
      catch case NonFatal(_) => None
    }

  def submitLive(user: String, ops: RoundOps): Boolean =
    session(user).exists { s =>
      try stub.submitLive(ppb.SubmitLiveRequest(user, s, Some(ProviderProto.toProto(ops)))).accepted
      catch case NonFatal(_) => false
    }

  def collectReceipt(user: String, roundId: Long): Option[_root_.provider.StoredReceipt] =
    session(user).flatMap { s =>
      try
        val r = stub.collectReceipt(ppb.CollectReceiptRequest(user, s, roundId))
        if r.found then r.receipt.map(ProviderProto.fromProto) else None
      catch case NonFatal(_) => None
    }

  def collectAll(user: String): Vector[_root_.provider.StoredReceipt] =
    session(user).fold(Vector.empty) { s =>
      try
        stub
          .collectAll(ppb.CollectAllRequest(user, s))
          .receipts
          .map(ProviderProto.fromProto)
          .toVector
      catch case NonFatal(_) => Vector.empty
    }
