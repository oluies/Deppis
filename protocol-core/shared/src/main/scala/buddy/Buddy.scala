package buddy

/** Buddy relationships and the buddy book (T024; FR-002, FR-015, FR-018).
  *
  *   - A pair has exactly one relationship; re-adding an active pair is rejected (no dup, FR-002).
  *   - States: Pending -> Confirmed (safety number matched) or -> Removed (mismatch / removal).
  *   - The active-buddy count is capped at 512 (FR-015); the 513th add is rejected predictably.
  *   - Removal stops future delivery (FR-018) without deleting history that would be needed to
  *     avoid re-creating a duplicate.
  *
  * Immutable: every mutator returns a new `BuddyBook`. */
object Buddy:
  val MaxBuddies: Int = 512

  enum BuddyState:
    case Pending, Confirmed, Removed

  final case class BuddyRelationship(
      pairId: String,
      safetyNumber: String,
      state: BuddyState,
      pairKey: Array[Byte]
  )

  final class BuddyBook private (private val rels: Map[String, BuddyRelationship]):
    /** Active (non-removed) buddies — the quantity the 512 cap applies to. */
    def size: Int = rels.valuesIterator.count(_.state != BuddyState.Removed)
    def confirmedCount: Int = rels.valuesIterator.count(_.state == BuddyState.Confirmed)
    def get(pairId: String): Option[BuddyRelationship] = rels.get(pairId)

    def add(rel: BuddyRelationship): Either[String, BuddyBook] =
      if rels.get(rel.pairId).exists(_.state != BuddyState.Removed) then Left("duplicate buddy")
      else if size >= MaxBuddies then Left(s"buddy cap $MaxBuddies reached")
      else Right(BuddyBook(rels.updated(rel.pairId, rel)))

    def confirm(pairId: String, matched: Boolean): Either[String, BuddyBook] =
      rels.get(pairId) match
        case Some(r) if r.state == BuddyState.Pending =>
          val next = if matched then BuddyState.Confirmed else BuddyState.Removed
          Right(BuddyBook(rels.updated(pairId, r.copy(state = next))))
        case Some(_) => Left("relationship is not pending")
        case None => Left("unknown pair")

    def remove(pairId: String): Either[String, BuddyBook] =
      rels.get(pairId) match
        case Some(r) => Right(BuddyBook(rels.updated(pairId, r.copy(state = BuddyState.Removed))))
        case None => Left("unknown pair")

  object BuddyBook:
    def empty: BuddyBook = BuddyBook(Map.empty)
    private def apply(m: Map[String, BuddyRelationship]): BuddyBook = new BuddyBook(m)
