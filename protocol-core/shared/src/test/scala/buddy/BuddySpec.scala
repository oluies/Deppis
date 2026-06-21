package buddy

import org.scalatest.funsuite.AnyFunSuite
import Buddy.*

class BuddySpec extends AnyFunSuite:

  private def rel(id: String, state: BuddyState = BuddyState.Pending): BuddyRelationship =
    BuddyRelationship(id, "00000 00000 00000 00000 00000 00000", state, Array[Byte](1, 2, 3))

  test("add then confirm transitions Pending -> Confirmed (FR-001/FR-002)"):
    val book = BuddyBook.empty.add(rel("p1")).flatMap(_.confirm("p1", matched = true)).toOption.get
    assert(book.get("p1").get.state == BuddyState.Confirmed)
    assert(book.confirmedCount == 1)

  test("mismatched safety number rejects the pairing (Pending -> Removed)"):
    val book = BuddyBook.empty.add(rel("p1")).flatMap(_.confirm("p1", matched = false)).toOption.get
    assert(book.get("p1").get.state == BuddyState.Removed)
    assert(book.size == 0)

  test("re-adding an active pair is rejected as duplicate (FR-002)"):
    val once = BuddyBook.empty.add(rel("p1")).toOption.get
    assert(once.add(rel("p1")).isLeft)

  test("removed pair stops counting and can be re-added (FR-018)"):
    val removed = BuddyBook.empty.add(rel("p1")).flatMap(_.remove("p1")).toOption.get
    assert(removed.size == 0)
    assert(removed.add(rel("p1")).isRight)

  // T024a — the 512-buddy cap (FR-015)
  test("accepts up to 512 buddies and rejects the 513th predictably (FR-015)"):
    val full = (1 to MaxBuddies).foldLeft(BuddyBook.empty) { (book, i) =>
      book.add(rel(s"p$i")).toOption.get
    }
    assert(full.size == MaxBuddies)
    val over = full.add(rel("p513"))
    assert(over == Left(s"buddy cap $MaxBuddies reached"))

  test("after removing one at the cap, a new buddy can be added"):
    val full =
      (1 to MaxBuddies).foldLeft(BuddyBook.empty)((b, i) => b.add(rel(s"p$i")).toOption.get)
    val freed = full.remove("p1").toOption.get
    assert(freed.add(rel("pNew")).isRight)
