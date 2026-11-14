package provider

import engine.{RoundOps, RoundReceipt, RoundSignal}

import java.nio.ByteBuffer

/** Fixed binary encodings of what [[JdbcProviderStore]] persists. Fields are opaque bytes, written
  * verbatim, length-prefixed. Decoding is bounds-checked and fails loudly: these bytes come from the
  * provider's own store, so a malformed record means corruption, not an attacker to stay quiet for. */
private[provider] object ProviderCodec:
  private def putBytes(b: ByteBuffer, a: Array[Byte]): Unit = { b.putInt(a.length); b.put(a) }
  private def getBytes(b: ByteBuffer): Array[Byte] =
    val n = b.getInt()
    if n < 0 || n > b.remaining() then throw IllegalStateException("corrupt provider record")
    val a = new Array[Byte](n); b.get(a); a
  private def sized(n: Int)(f: ByteBuffer => Unit): Array[Byte] =
    val b = ByteBuffer.allocate(n); f(b); b.array()

  def encodeOps(o: RoundOps): Array[Byte] =
    val fields = Seq(o.writeToken, o.frame, o.signal.label, o.fallbackSignal.label, o.readToken)
    sized(8 + 8 + fields.map(4 + _.length).sum) { b =>
      b.putLong(o.roundId)
      putBytes(b, o.writeToken); putBytes(b, o.frame)
      putBytes(b, o.signal.label); b.putInt(o.signal.bit)
      putBytes(b, o.fallbackSignal.label); b.putInt(o.fallbackSignal.bit)
      putBytes(b, o.readToken)
    }

  def decodeOps(a: Array[Byte]): RoundOps =
    try
      val b = ByteBuffer.wrap(a)
      val round = b.getLong()
      val write = getBytes(b); val frame = getBytes(b)
      val sig = RoundSignal(getBytes(b), b.getInt())
      val fb = RoundSignal(getBytes(b), b.getInt())
      val read = getBytes(b)
      if b.hasRemaining then throw IllegalStateException("corrupt provider record")
      RoundOps(round, write, frame, sig, fb, read)
    catch
      case _: java.nio.BufferUnderflowException =>
        throw IllegalStateException("corrupt provider record")

  def encodeReceipt(r: StoredReceipt): Array[Byte] =
    val retrieved = r.receipt.retrieved.getOrElse(Array.emptyByteArray)
    sized(8 + 3 + 4 + retrieved.length + 4 + r.digest.length) { b =>
      b.putLong(r.receipt.roundId)
      b.put(if r.receipt.ranLive then 1.toByte else 0.toByte)
      b.put(if r.receipt.writeAccepted then 1.toByte else 0.toByte)
      b.put(if r.receipt.retrieved.isDefined then 1.toByte else 0.toByte)
      putBytes(b, retrieved); putBytes(b, r.digest)
    }

  def decodeReceipt(a: Array[Byte]): StoredReceipt =
    try
      val b = ByteBuffer.wrap(a)
      val round = b.getLong()
      val ranLive = b.get() == 1; val accepted = b.get() == 1; val hasRetrieved = b.get() == 1
      val retrieved = getBytes(b); val digest = getBytes(b)
      if b.hasRemaining then throw IllegalStateException("corrupt provider record")
      StoredReceipt(
        RoundReceipt(round, ranLive, accepted, Option.when(hasRetrieved)(retrieved)),
        digest
      )
    catch
      case _: java.nio.BufferUnderflowException =>
        throw IllegalStateException("corrupt provider record")
