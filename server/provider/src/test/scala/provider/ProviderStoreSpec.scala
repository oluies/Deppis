package provider

import crypto.Crypto
import engine.{BuddyRole, Engine, RoundOps, RoundReceipt, RoundSignal}
import org.scalatest.funsuite.AnyFunSuite
import ping.DevNotificationServer

import java.nio.file.{Files, Path}
import scala.util.Random

/** The [[ProviderStore]] contract, run against every implementation — in-memory, embedded H2 (a
  * file, PostgreSQL mode) and a real Postgres — plus what only a persistent store can do: survive a
  * restart (`design/offline-delegation.md` §5).
  *
  * Postgres runs when `PROVIDER_PG_URL` (a `jdbc:postgresql://…` URL) is set, and cancels otherwise —
  * unless `REQUIRE_POSTGRES=1`, which turns "no database" into a FAILURE. CI's JVM job sets both, so
  * the Postgres run cannot silently drop out (a cancelled test reads exactly like a passing one). */
class ProviderStoreSpec extends AnyFunSuite:

  private val rng = Random(7)
  private def bytes(n: Int) = Array.fill(n)(rng.nextInt().toByte)
  private def ops(round: Long) = RoundOps(
    round,
    bytes(32),
    bytes(256),
    RoundSignal(bytes(32), rng.nextInt(512)),
    RoundSignal(bytes(32), rng.nextInt(512)),
    bytes(32)
  )
  private def receipt(round: Long, retrieved: Option[Array[Byte]]) =
    StoredReceipt(RoundReceipt(round, rng.nextBoolean(), rng.nextBoolean(), retrieved), bytes(64))
  private def same(a: RoundOps, b: RoundOps) =
    a.roundId == b.roundId && a.writeToken.sameElements(b.writeToken) &&
      a.frame.sameElements(b.frame) && a.signal.label.sameElements(b.signal.label) &&
      a.signal.bit == b.signal.bit && a.fallbackSignal.label.sameElements(b.fallbackSignal.label) &&
      a.fallbackSignal.bit == b.fallbackSignal.bit && a.readToken.sameElements(b.readToken)
  private def same(a: StoredReceipt, b: StoredReceipt) =
    a.receipt.roundId == b.receipt.roundId && a.receipt.ranLive == b.receipt.ranLive &&
      a.receipt.writeAccepted == b.receipt.writeAccepted &&
      a.receipt.retrieved.map(_.toVector) == b.receipt.retrieved.map(_.toVector) &&
      a.digest.sameElements(b.digest)

  private def tempDb(): Path = Files.createTempDirectory("provider-store").resolve("store")

  /** Each backend: a name and a way to open a fresh store. Postgres tests share one database, so
    * every test uses its own random user names and never sees another test's rows. */
  private val backends: Seq[(String, () => ProviderStore)] = Seq(
    "in-memory" -> (() => InMemoryProviderStore()),
    "H2 (embedded)" -> (() => JdbcProviderStore.embedded(tempDb())),
    "Postgres" -> (() =>
      sys.env.get("PROVIDER_PG_URL") match
        case Some(url) => JdbcProviderStore.postgres(url)
        case None if sys.env.get("REQUIRE_POSTGRES").contains("1") =>
          fail("REQUIRE_POSTGRES=1 but PROVIDER_PG_URL is not set")
        case None => cancel("PROVIDER_PG_URL not set; Postgres store tests skipped")
    )
  )

  private def withStore(open: () => ProviderStore)(body: ProviderStore => Unit): Unit =
    val s = open()
    try body(s)
    finally
      s match
        case c: AutoCloseable => c.close()
        case _ => ()

  private def user() = s"u-${rng.alphanumeric.take(12).mkString}"

  for (name, open) <- backends do
    test(s"$name: registrations round-trip, keep their order, and are replaced in place"):
      withStore(open) { s =>
        val (a, b) = (user(), user())
        val ha = bytes(32)
        s.putUser(StoredUser(a, bytes(32), Some(ha)))
        s.putUser(StoredUser(b, bytes(32), None))
        val label = bytes(32)
        s.putUser(StoredUser(a, label, Some(ha))) // replace a: same place in the order
        val mine = s.users.filter(u => u.user == a || u.user == b)
        assert(mine.map(_.user) == Vector(a, b), "registration order is kept")
        assert(
          mine.head.clientLabel.sameElements(label) && mine.head.sessionHash.exists(
            _.sameElements(ha)
          )
        )
        assert(mine(1).sessionHash.isEmpty, "no session hash is stored as none")
      }

    test(s"$name: a bundle replace is whole — the old slots are gone, the new ones exact"):
      withStore(open) { s =>
        val u = user()
        s.replaceBundle(u, (10L until 20L).map(ops).toVector)
        val fresh = (30L until 35L).map(ops).toVector
        s.replaceBundle(u, fresh)
        assert(s.slotCount(u) == 5)
        assert(s.takeSlot(u, 10L).isEmpty, "nothing of the old bundle survives")
        val got = s.takeSlot(u, 32L).get
        assert(same(got, fresh(2)), "a slot comes back byte for byte")
        assert(s.takeSlot(u, 32L).isEmpty, "a slot is taken exactly once")
        s.dropSlotsBefore(u, 34L)
        assert(s.slotCount(u) == 1, "slots for rounds before 34 are dropped")
      }

    test(s"$name: receipts are capped at the newest maxKept, taken once, drained in order"):
      withStore(open) { s =>
        val u = user()
        val rs = (1L to 8L).map(r => receipt(r, if r % 2 == 0 then Some(bytes(256)) else None))
        rs.foreach(r => s.putReceipt(u, r, maxKept = 5))
        assert(s.receiptCount(u) == 5, "only the newest 5 are kept")
        assert(s.takeReceipt(u, 2L).isEmpty, "the oldest were evicted")
        assert(same(s.takeReceipt(u, 6L).get, rs(5)), "a receipt comes back byte for byte")
        assert(s.takeReceipt(u, 6L).isEmpty, "and is taken exactly once")
        val rest = s.drainReceipts(u)
        assert(rest.map(_.receipt.roundId) == Vector(4L, 5L, 7L, 8L), "drained oldest first")
        assert(rest.zip(Seq(rs(3), rs(4), rs(6), rs(7))).forall(same(_, _)))
        assert(s.receiptCount(u) == 0)
      }

    test(s"$name: an empty retrieved frame is kept distinct from no frame"):
      withStore(open) { s =>
        val u = user()
        s.putReceipt(u, receipt(1L, Some(Array.emptyByteArray)), maxKept = 10)
        s.putReceipt(u, receipt(2L, None), maxKept = 10)
        assert(s.takeReceipt(u, 1L).get.receipt.retrieved.exists(_.isEmpty))
        assert(s.takeReceipt(u, 2L).get.receipt.retrieved.isEmpty)
      }

  // ================================================================ surviving a restart (H2 file)

  test("H2: registrations, slots and receipts survive closing and reopening the store"):
    val path = tempDb()
    val u = user()
    val label = bytes(32)
    val hash = bytes(32)
    val slots = (5L until 9L).map(ops).toVector
    val r = receipt(3L, Some(bytes(256)))
    val first = JdbcProviderStore.embedded(path)
    first.putUser(StoredUser(u, label, Some(hash)))
    first.replaceBundle(u, slots)
    first.putReceipt(u, r, maxKept = 10)
    first.close()

    val again = JdbcProviderStore.embedded(path)
    try
      val reg = again.users.find(_.user == u).get
      assert(reg.clientLabel.sameElements(label) && reg.sessionHash.exists(_.sameElements(hash)))
      assert(again.slotCount(u) == 4)
      assert(same(again.takeSlot(u, 7L).get, slots(2)))
      assert(same(again.takeReceipt(u, 3L).get, r))
    finally again.close()

  test("H2: a provider rebuilt on the reopened store keeps its users and runs their bundles"):
    val path = tempDb()
    def backend() = DevProviderBackend(notifications =
      DevNotificationServer(Array.tabulate(Crypto.KeyBytes)(_.toByte))
    )
    val engine = Engine(clientLabel = "alice".getBytes)
    engine.addBuddy("oob".getBytes, BuddyRole.Initiator, peerNotifyLabel = "bob".getBytes): Unit
    val hash = bytes(32)

    val store1 = JdbcProviderStore.embedded(path)
    val p1 = Provider(backend(), store1, maxHorizon = 50)
    p1.register("alice", "alice".getBytes, Some(hash)).toOption.get
    p1.uploadBundle("alice", engine.buildBundle(1, 50).toOption.get).toOption.get
    p1.openRound(1).toOption.get
    assert(p1.closeRound(1) == Right(1), "round 1 ran alice's slot")
    store1.close() // the provider process goes away

    val store2 = JdbcProviderStore.embedded(path)
    try
      val p2 = Provider(backend(), store2, maxHorizon = 50)
      assert(p2.isRegistered("alice"), "the registration survived")
      assert(p2.sessionHashOf("alice").exists(_.sameElements(hash)), "and so did the session hash")
      assert(store2.slotCount("alice") == 49, "the bundle survived, less the slot that ran")
      p2.openRound(2).toOption.get
      assert(p2.closeRound(2) == Right(1), "after the restart the stored bundle still runs")
      assert(store2.receiptCount("alice") == 2, "and the receipts from both lifetimes are kept")
    finally store2.close()
