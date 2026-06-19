package session

import frame.Frame
import token.RetrievalToken

/** A prepared outgoing message: its fixed-size frame and the single-use retrieval token a buddy
  * will use to fetch it. */
final case class Outgoing(frame: Array[Byte], retrievalToken: Array[Byte])

private[session] final case class ConversationState(
    selfId: String,
    buddyId: String,
    pairKey: Array[Byte],
    sendCounter: Long,
    queue: Vector[Array[Byte]]
)

/** Per-buddy conversation state (T034, FR-006). Each buddy has its own independent send queue
  * and monotone send counter, keyed by `pairId`, so operations on one conversation never block
  * or perturb another — the user can hold many conversations at once.
  *
  * Retrieval tokens are derived as `HMAC(pairKey, selfId, buddyId, counter)`. The `selfId`/
  * `buddyId` ordering domain-separates the two send directions, so A→B and B→A never collide
  * even at equal counters; the monotone counter keeps each direction's tokens non-recurrent
  * (FR-014). Immutable: every operation returns a new `Conversations`. */
final class Conversations private (private val convs: Map[String, ConversationState]):

  /** Register a conversation. No-op if `pairId` already exists, so a re-register can never rewind
    * an in-progress counter (which would re-derive used tokens) or drop queued messages. */
  def register(pairId: String, selfId: String, buddyId: String, pairKey: Array[Byte]): Conversations =
    if convs.contains(pairId) then this
    else new Conversations(convs.updated(pairId, ConversationState(selfId, buddyId, pairKey, 0L, Vector.empty)))

  def pending(pairId: String): Int = convs.get(pairId).map(_.queue.size).getOrElse(0)

  def enqueue(pairId: String, plaintext: Array[Byte]): Either[String, Conversations] =
    convs.get(pairId) match
      case None     => Left(s"unknown conversation $pairId")
      case Some(st) => Right(new Conversations(convs.updated(pairId, st.copy(queue = st.queue :+ plaintext))))

  /** Pop and prepare the next outgoing message for ONE buddy, independent of every other
    * conversation. Advances only that buddy's counter and queue. */
  def dequeueSend(pairId: String): Either[String, (Outgoing, Conversations)] =
    convs.get(pairId) match
      case None                         => Left(s"unknown conversation $pairId")
      case Some(st) if st.queue.isEmpty => Left(s"no pending message for $pairId")
      case Some(st) =>
        Frame.pad(st.queue.head).map { fr =>
          val counter = st.sendCounter + 1
          val token   = RetrievalToken.derive(st.pairKey, st.selfId, st.buddyId, counter)
          val next    = st.copy(sendCounter = counter, queue = st.queue.tail)
          (Outgoing(fr, token), new Conversations(convs.updated(pairId, next)))
        }

object Conversations:
  def empty: Conversations = new Conversations(Map.empty)
