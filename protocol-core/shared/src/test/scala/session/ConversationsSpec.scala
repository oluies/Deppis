package session

import frame.Frame
import token.RetrievalToken
import org.scalatest.funsuite.AnyFunSuite

class ConversationsSpec extends AnyFunSuite:

  private val key = Array.tabulate(32)(_.toByte)
  private def reg(pairId: String, self: String = "A", buddy: String = "B") =
    Conversations.empty.register(pairId, self, buddy, key)

  test("dequeue prepares a 256-byte frame and a retrieval token; counter advances (FR-006/FR-014)"):
    val c1 = reg("p1").enqueue("p1", "hello".getBytes).toOption.get
    val (out, c2) = c1.dequeueSend("p1").toOption.get
    assert(out.frame.length == Frame.Size)
    assert(out.retrievalToken.length == RetrievalToken.Length)
    assert(c2.pending("p1") == 0)

  test("successive sends to one buddy use distinct (non-recurrent) tokens"):
    val c =
      reg("p1").enqueue("p1", "a".getBytes).toOption.get.enqueue("p1", "b".getBytes).toOption.get
    val (o1, c1) = c.dequeueSend("p1").toOption.get
    val (o2, _) = c1.dequeueSend("p1").toOption.get
    assert(!RetrievalToken.equalsCT(o1.retrievalToken, o2.retrievalToken))

  test(
    "send direction is domain-separated: A->B and B->A tokens differ at equal counters (FR-014)"
  ):
    val ab = reg("pair", "A", "B")
      .enqueue("pair", "m".getBytes)
      .toOption
      .get
      .dequeueSend("pair")
      .toOption
      .get
      ._1
    val ba = reg("pair", "B", "A")
      .enqueue("pair", "m".getBytes)
      .toOption
      .get
      .dequeueSend("pair")
      .toOption
      .get
      ._1
    assert(!RetrievalToken.equalsCT(ab.retrievalToken, ba.retrievalToken))

  test("re-register is a no-op: counter and queue are preserved (no token rewind, FR-014)"):
    val c = reg("p").enqueue("p", "x".getBytes).toOption.get
    val c2 = c.register("p", "A", "B", key) // must not reset
    assert(c2.pending("p") == 1)

  // T033 — three concurrent conversations, none blocking another
  test(
    "conversations are independent: enqueue/dequeue on one buddy doesn't affect others (FR-006)"
  ):
    val c = reg("a")
      .register("b", "A", "C", key)
      .register("c", "A", "D", key)
      .enqueue("a", "1".getBytes)
      .toOption
      .get
    assert(c.pending("a") == 1 && c.pending("b") == 0 && c.pending("c") == 0)
    val c2 = c.dequeueSend("a").toOption.get._2
    assert(c2.pending("a") == 0 && c2.pending("b") == 0)

  test("a new conversation proceeds without disturbing an in-progress one"):
    val c = reg("a").enqueue("a", "x".getBytes).toOption.get
    val c2 = c.register("b", "A", "C", key).enqueue("b", "y".getBytes).toOption.get
    assert(c2.pending("a") == 1 && c2.pending("b") == 1)

  // T033a — scale: up to 512 simultaneous conversations, each independently drainable
  test("512 simultaneous conversations each prepare a frame, none blocked (SC-005)"):
    val full = (0 until 512).foldLeft(Conversations.empty) { (c, i) =>
      c.register(s"p$i", "self", s"b$i", key).enqueue(s"p$i", s"msg-$i".getBytes).toOption.get
    }
    (0 until 512).foreach { i =>
      val r = full.dequeueSend(s"p$i")
      assert(r.isRight && r.toOption.get._1.frame.length == Frame.Size)
    }

  test("operations on an unknown conversation fail cleanly"):
    assert(Conversations.empty.enqueue("nope", Array()).isLeft)
    assert(Conversations.empty.dequeueSend("nope").isLeft)
