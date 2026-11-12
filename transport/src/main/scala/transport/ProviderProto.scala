package transport

import com.google.protobuf.ByteString
import engine.{RoundOps, RoundReceipt, RoundSignal}
import metadatamessenger.provider.v1.provider as ppb

/** Conversions between the engine's round types and `provider.proto`. Opaque bytes in, opaque bytes
  * out — no field is interpreted. */
private[transport] object ProviderProto:
  private def bs(b: Array[Byte]): ByteString = ByteString.copyFrom(b)

  def toProto(s: RoundSignal): ppb.Signal = ppb.Signal(label = bs(s.label), bit = s.bit)
  def fromProto(s: Option[ppb.Signal]): RoundSignal =
    val p = s.getOrElse(ppb.Signal())
    RoundSignal(p.label.toByteArray, p.bit)

  def toProto(o: RoundOps): ppb.RoundOps =
    ppb.RoundOps(
      roundId = o.roundId,
      writeToken = bs(o.writeToken),
      frame = bs(o.frame),
      signal = Some(toProto(o.signal)),
      fallbackSignal = Some(toProto(o.fallbackSignal)),
      readToken = bs(o.readToken)
    )
  def fromProto(o: ppb.RoundOps): RoundOps =
    RoundOps(
      o.roundId,
      o.writeToken.toByteArray,
      o.frame.toByteArray,
      fromProto(o.signal),
      fromProto(o.fallbackSignal),
      o.readToken.toByteArray
    )

  def toProto(r: _root_.provider.StoredReceipt): ppb.Receipt =
    ppb.Receipt(
      roundId = r.receipt.roundId,
      ranLive = r.receipt.ranLive,
      writeAccepted = r.receipt.writeAccepted,
      hasRetrieved = r.receipt.retrieved.isDefined,
      retrieved = r.receipt.retrieved.fold(ByteString.EMPTY)(bs),
      digest = bs(r.digest)
    )
  def fromProto(r: ppb.Receipt): _root_.provider.StoredReceipt =
    _root_.provider.StoredReceipt(
      RoundReceipt(
        r.roundId,
        r.ranLive,
        r.writeAccepted,
        Option.when(r.hasRetrieved)(r.retrieved.toByteArray)
      ),
      r.digest.toByteArray
    )
