package store.dev

import store.ObliviousStore
import frame.Frame
import privacy.Privacy
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap

/** Dev in-memory ObliviousStore (T031). Provides NO access-pattern privacy — the map lookup is
  * content-dependent — so this backend is labeled `DEV, NO METADATA PRIVACY` (Constitution IV)
  * and `metadataPrivate` is false. It still enforces the structural invariants that the real
  * store must also keep: frames are exactly 256 bytes, a write token is used at most once
  * (no two messages under one token), and a retrieval token is single-use / non-recurrent
  * (FR-014). */
final class DevObliviousStore extends ObliviousStore:
  private val frames = new ConcurrentHashMap[String, Array[Byte]]()

  val label: String = Privacy.DevLabel
  def metadataPrivate: Boolean = false

  def write(writeToken: Array[Byte], frame: Array[Byte]): Either[String, Unit] =
    if frame.length != Frame.Size then Left(s"frame ${frame.length} != ${Frame.Size}")
    else
      val k = key(writeToken)
      // putIfAbsent == null means the slot was empty; a non-null prior value is token reuse.
      if frames.putIfAbsent(k, frame) != null then Left("write token already used")
      else Right(())

  def read(retrievalToken: Array[Byte]): Either[String, Option[Array[Byte]]] =
    // remove() makes the token single-use: a second read returns None (non-recurrence, FR-014).
    Right(Option(frames.remove(key(retrievalToken))))

  private def key(token: Array[Byte]): String = Base64.getEncoder.encodeToString(token)
