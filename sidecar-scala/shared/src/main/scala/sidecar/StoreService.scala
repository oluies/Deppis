package sidecar

import cats.effect.Sync
import cats.effect.std.Mutex
import cats.syntax.all.*
import com.google.protobuf.ByteString
import metadatamessenger.store.v1.store as pb
import org.http4s.Headers

/** The benchmark's gRPC front for [[ObliviousStore]] — the Scala counterpart of
  * `oblivious-sidecar/src/grpc.rs`, deliberately mirroring its semantics so the two are measuring
  * the same work:
  *
  *   - `batch_size` (public) must match the number of entries actually sent;
  *   - every entry is validated BEFORE anything is applied, so a malformed entry cannot leave the
  *     store half-mutated or burn earlier single-use tokens;
  *   - a read yields a fixed 257-byte `sealed_result = frame ‖ found-tag`, uniform in length
  *     whether the token hit or missed.
  *
  * As in the Rust dev build, `sealed_result` is CLEARTEXT here: hit-vs-miss is distinguishable by
  * content. That is acceptable only under the `DEV, NO METADATA PRIVACY` label, and this build
  * additionally makes no privacy claim at all (see [[ObliviousStore]]).
  *
  * The store lives behind a real [[cats.effect.std.Mutex]], mirroring the `Mutex<ObliviousStore>`
  * the Rust front holds — so neither side gets to look faster by allowing concurrent mutation the
  * other forbids.
  *
  * This was a `Ref` used as a lock (`lock.flatModify(_ => ((), delay(f)))`), which is NOT one:
  * `flatModify` updates the ref atomically and then runs the returned effect with no exclusion at
  * all, so two concurrent calls both proceed into the body. [[ObliviousStore]] mutates shared
  * arrays and is not thread-safe, so that was a live data race — and a benchmark advantage the
  * Rust side was not given. It went unnoticed because the Scala Native link was defaulting to a
  * SINGLE-THREADED binary; enabling multithreading is what made it reachable.
  */
final class StoreService[F[_]: Sync](mutex: Mutex[F], store: ObliviousStore)
    extends pb.ObliviousStore[F]:

  import ObliviousStore.{FrameLen, TokenLen}

  private def exact(src: ByteString, n: Int, field: String): F[Array[Byte]] =
    if src.size != n then
      Sync[F].raiseError(new IllegalArgumentException(s"$field must be $n bytes, got ${src.size}"))
    else Sync[F].pure(src.toByteArray())

  private def checkBatch(declared: Int, actual: Int): F[Unit] =
    Sync[F]
      .raiseError(new IllegalArgumentException(s"batch_size $declared does not match $actual"))
      .whenA(declared != actual)

  /** Runs `f` with genuinely exclusive access to the (mutable, not thread-safe) store. */
  private def exclusive[A](f: => A): F[A] =
    mutex.lock.surround(Sync[F].delay(f))

  def writeBatch(request: pb.WriteBatchRequest, ctx: Headers): F[pb.WriteBatchResponse] =
    for
      _ <- checkBatch(request.batchSize, request.entries.size)
      parsed <- request.entries.toList.traverse { e =>
        (exact(e.writeToken, TokenLen, "write_token"), exact(e.frame, FrameLen, "frame")).tupled
      }
      _ <- exclusive {
        // A full store silently drops, as in the Rust dev front; non-recurrence is the store's job.
        parsed.foreach((token, frame) => store.write(token, frame): Unit)
      }
    yield pb.WriteBatchResponse(roundId = request.roundId)

  def readBatch(request: pb.ReadBatchRequest, ctx: Headers): F[pb.ReadBatchResponse] =
    for
      _ <- checkBatch(request.batchSize, request.entries.size)
      tokens <- request.entries.toList.traverse(e =>
        exact(e.retrievalToken, TokenLen, "retrieval_token")
      )
      results <- exclusive {
        val out = new Array[Byte](FrameLen)
        tokens.map { token =>
          val found = store.readSealed(token, out)
          val sealedResult = new Array[Byte](FrameLen + 1)
          System.arraycopy(out, 0, sealedResult, 0, FrameLen)
          sealedResult(FrameLen) = if found then 1 else 0
          pb.ReadResult(sealedResult = ByteString.copyFrom(sealedResult))
        }
      }
    yield pb.ReadBatchResponse(roundId = request.roundId, results = results)
