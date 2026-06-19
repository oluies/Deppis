package anon

/** Anonymity-layer interface (T016, Constitution VIII). A dev implementation (single honest
  * shuffler, NO differential-privacy guarantee) and a target implementation (Groove mixnet)
  * both satisfy this; the active one is chosen by config. `metadataPrivate` is false for any
  * non-target/unattested implementation and drives the labeling rule (Constitution IV). */
trait AnonymityLayer:
  def metadataPrivate: Boolean
  def submit(roundId: Long, frame: Array[Byte]): Either[String, Unit]
  def fetch(roundId: Long, count: Int): Either[String, Seq[Array[Byte]]]
