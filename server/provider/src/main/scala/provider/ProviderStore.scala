package provider

import engine.{RoundOps, RoundReceipt}

import scala.collection.mutable

/** What the untrusted service provider keeps per user (`design/offline-delegation.md` §5): the
  * standing bundle's unexecuted slots and the receipts not yet collected. Nothing else. Keyed by
  * USER, not device (open question 4: multi-device should share one per-user schedule).
  *
  * Every value is opaque to the provider by construction — tokens are PRF outputs, frames are
  * ciphertext, and from Phase 4 the write, read and signal are sealed to the enclaves and the
  * digest and read response to the device. Until then the dev build stores them in the clear,
  * which is one reason provider routing is labeled `DEV, NO METADATA PRIVACY`.
  *
  * An interface so a Postgres or embedded-KV store can replace [[InMemoryProviderStore]] (`plan.md`);
  * implementations must make [[replaceBundle]] atomic and respect the bounds callers rely on. */
trait ProviderStore:
  /** Replace `user`'s standing bundle with `slots` (one per round, ascending), ATOMICALLY: a
    * concurrent reader sees either the whole old bundle or the whole new one. */
  def replaceBundle(user: String, slots: Vector[RoundOps]): Unit

  /** Remove and return `user`'s slot for `roundId`, if the bundle has one. */
  def takeSlot(user: String, roundId: Long): Option[RoundOps]

  /** Drop every slot of `user`'s bundle for a round before `roundId` (§5: a slot is deleted when its
    * round passes, whether or not it ran). */
  def dropSlotsBefore(user: String, roundId: Long): Unit

  /** How many unexecuted slots `user` has (observability + tests). */
  def slotCount(user: String): Int

  /** Keep a receipt (with the round's phase-A digest) for `user`, evicting the oldest beyond
    * `maxKept` (§5: at most H). */
  def putReceipt(user: String, receipt: StoredReceipt, maxKept: Int): Unit

  /** Remove and return `user`'s receipt for `roundId`, if kept. */
  def takeReceipt(user: String, roundId: Long): Option[StoredReceipt]

  /** Remove and return all of `user`'s kept receipts, oldest first. */
  def drainReceipts(user: String): Vector[StoredReceipt]

  /** How many receipts `user` has kept (observability + tests). */
  def receiptCount(user: String): Int

/** A round's receipt as the provider keeps it, with that round's phase-A digest (§3.1). */
final case class StoredReceipt(receipt: RoundReceipt, digest: Array[Byte])

/** The in-memory [[ProviderStore]] (dev). Every operation is atomic under one lock. */
final class InMemoryProviderStore extends ProviderStore:
  private val bundles = mutable.Map.empty[String, mutable.TreeMap[Long, RoundOps]]
  private val receipts = mutable.Map.empty[String, mutable.TreeMap[Long, StoredReceipt]]

  def replaceBundle(user: String, slots: Vector[RoundOps]): Unit = synchronized {
    bundles(user) = mutable.TreeMap.from(slots.map(s => s.roundId -> s))
  }

  def takeSlot(user: String, roundId: Long): Option[RoundOps] = synchronized {
    bundles.get(user).flatMap(_.remove(roundId))
  }

  def dropSlotsBefore(user: String, roundId: Long): Unit = synchronized {
    bundles.get(user).foreach(b => b.keys.takeWhile(_ < roundId).toVector.foreach(b.remove))
  }

  def slotCount(user: String): Int = synchronized(bundles.get(user).fold(0)(_.size))

  def putReceipt(user: String, receipt: StoredReceipt, maxKept: Int): Unit = synchronized {
    val m = receipts.getOrElseUpdate(user, mutable.TreeMap.empty)
    m(receipt.receipt.roundId) = receipt
    while m.size > maxKept do m.remove(m.firstKey): Unit
  }

  def takeReceipt(user: String, roundId: Long): Option[StoredReceipt] = synchronized {
    receipts.get(user).flatMap(_.remove(roundId))
  }

  def drainReceipts(user: String): Vector[StoredReceipt] = synchronized {
    receipts.remove(user).fold(Vector.empty)(_.values.toVector)
  }

  def receiptCount(user: String): Int = synchronized(receipts.get(user).fold(0)(_.size))
