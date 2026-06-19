package session

import frame.Frame
import token.RetrievalToken
import org.scalatest.funsuite.AnyFunSuite

class ConversationsSpec extends AnyFunSuite:

  private val key = Array.tabulate(32)(_.toByte)

  test("dequeue prepares a 256-byte frame and a retrieval token; counter advances (FR-006/FR-014)"):
    val c0 = Conversations.empty.register("p1", key)
    val c1 = c0.enqueue("p1", "hello".getBytes).toOption.get
    val (out, c2) = c1.dequeueSend("p1").toOption.get
    assert(out.frame.length == Frame.Size)
    assert(out.retrievalToken.length == RetrievalToken.Length)
    assert(c2.pending("p1") == 0)

  test("successive sends to one buddy use distinct (non-recurrent) tokens"):
    val c = Conversations.empty.register("p1", key).enqueue("p1", "a".getBytes).toOption.get.enqueue("p1", "b".getBytes).toOption.get
    val (o1, c1) = c.dequeueSend("p1").toOption.get
    val (o2, _)  = c1.dequeueSend("p1").toOption.get
    assert(!RetrievalToken.equalsCT(o1.retrievalToken, o2.retrievalToken))

  // T033 — three concurrent conversations, none blocking another
  test("conversations are independent: enqueue/dequeue on one buddy doesn't affect others (FR-006)"):
    val c = Conversations.empty.register("a", key).register("b", key).register("c", key)
      .enqueue("a", "1".getBytes).toOption.get
    assert(c.pending("a") == 1 && c.pending("b") == 0 && c.pending("c") == 0)
    val c2 = c.dequeueSend("a").toOption.get._2
    assert(c2.pending("a") == 0 && c2.pending("b") == 0) // draining a left b untouched

  test("a new conversation proceeds without disturbing an in-progress one"):
    val c = Conversations.empty.register("a", key).enqueue("a", "x".getBytes).toOption.get
    val c2 = c.register("b", key).enqueue("b", "y".getBytes).toOption.get
    assert(c2.pending("a") == 1 && c2.pending("b") == 1)

  // T033a — scale: up to 512 simultaneous conversations, each independently drainable
  test("512 simultaneous conversations each prepare a frame, none blocked (SC-005)"):
    val full = (0 until 512).foldLeft(Conversations.empty) { (c, i) =>
      c.register(s"p$i", key).enqueue(s"p$i", s"msg-$i".getBytes).toOption.get
    }
    (0 until 512).foreach { i =>
      val r = full.dequeueSend(s"p$i")
      assert(r.isRight && r.toOption.get._1.frame.length == Frame.Size)
    }

  test("operations on an unknown conversation fail cleanly"):
    assert(Conversations.empty.enqueue("nope", Array()).isLeft)
    assert(Conversations.empty.dequeueSend("nope").isLeft)
