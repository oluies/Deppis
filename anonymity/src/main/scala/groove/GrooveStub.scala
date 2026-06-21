package groove

import anon.AnonymityLayer
import privacy.Privacy
import java.security.SecureRandom
import java.util.concurrent.{ConcurrentHashMap, CopyOnWriteArrayList}
import scala.jdk.CollectionConverters.*

/** Dev single-shuffler stand-in for the Groove mixnet (T061, D9). One honest shuffler buffers a
  * round's frames and returns them in shuffled order. It provides ordering permutation only —
  * **NO differential-privacy guarantee, no real mixnet** — so it is labeled `DEV, NO METADATA
  * PRIVACY` (Constitution IV) and `metadataPrivate` is false. It exists so the `AnonymityLayer`
  * has a working dev implementation without conflating the enclave and mixnet trust models; the
  * real Groove path (circuits, dead drops, oblivious fetch, DP noise) replaces it later.
  *
  * Per-round buffers are `CopyOnWriteArrayList`s so a `fetch` iterating a round cannot race a
  * concurrent `submit` (no `ConcurrentModificationException`). */
final class GrooveStub extends AnonymityLayer:
  private val rng = new SecureRandom()
  private val rounds = new ConcurrentHashMap[Long, CopyOnWriteArrayList[Array[Byte]]]()

  val label: String = Privacy.DevLabel
  def metadataPrivate: Boolean = false

  def submit(roundId: Long, frame: Array[Byte]): Either[String, Unit] =
    rounds.computeIfAbsent(roundId, _ => new CopyOnWriteArrayList[Array[Byte]]()).add(frame.clone())
    Right(())

  /** Single-shuffler: Fisher–Yates permute a snapshot of the round's frames and return up to
    * `count`, cloned so callers cannot mutate buffered state. The permutation hides submission
    * order within a round but is not a mix and adds no DP noise. */
  def fetch(roundId: Long, count: Int): Either[String, Seq[Array[Byte]]] =
    if count < 0 then Left("count must be >= 0")
    else
      val buf =
        Option(rounds.get(roundId)).map(_.asScala.toArray).getOrElse(Array.empty[Array[Byte]])
      var i = buf.length - 1
      while i > 0 do
        val j = rng.nextInt(i + 1)
        val t = buf(i); buf(i) = buf(j); buf(j) = t
        i -= 1
      Right(buf.take(count).map(_.clone()).toVector)
