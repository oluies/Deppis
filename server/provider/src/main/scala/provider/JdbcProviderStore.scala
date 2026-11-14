package provider

import engine.RoundOps

import java.sql.{Connection, DriverManager, PreparedStatement, ResultSet}
import scala.util.control.NonFatal

/** A [[ProviderStore]] that survives a restart (`design/offline-delegation.md` §5; `plan.md`:
  * "Postgres or embedded KV"). ONE implementation over JDBC, written against Postgres SQL:
  *   - [[JdbcProviderStore.embedded]] — H2 in a local file, in PostgreSQL mode: the default
  *     single-node store, pure Java, nothing to run beside the provider;
  *   - [[JdbcProviderStore.postgres]] — a Postgres server, for a real deployment.
  *
  * Every operation is one transaction on one connection, under one lock, so a bundle replace is
  * atomic and a slot or receipt is taken exactly once. That is right for one provider process; a
  * provider replicated over one database would need row locking instead.
  *
  * It stores what the in-memory store keeps and nothing more: registrations (notify label and the
  * SHA-256 of the session secret, never the secret), unexecuted slots, uncollected receipts — each
  * slot and receipt deleted when its round closes or it is collected. No sender identity is stored;
  * the values are as opaque as everything the provider relays (plaintext until Phase 4, hence DEV). */
final class JdbcProviderStore private (connect: () => Connection)
    extends ProviderStore,
      AutoCloseable:
  private val conn: Connection = connect()
  conn.setAutoCommit(false)
  tx { c =>
    val s = c.createStatement()
    try
      s.execute(
        "CREATE TABLE IF NOT EXISTS provider_user (user_id VARCHAR(256) PRIMARY KEY, " +
          "ordinal BIGINT NOT NULL, client_label BYTEA NOT NULL, session_hash BYTEA)"
      )
      s.execute(
        "CREATE TABLE IF NOT EXISTS provider_slot (user_id VARCHAR(256) NOT NULL, " +
          "round_id BIGINT NOT NULL, ops BYTEA NOT NULL, PRIMARY KEY (user_id, round_id))"
      )
      s.execute(
        "CREATE TABLE IF NOT EXISTS provider_receipt (user_id VARCHAR(256) NOT NULL, " +
          "round_id BIGINT NOT NULL, receipt BYTEA NOT NULL, PRIMARY KEY (user_id, round_id))"
      )
    finally s.close()
  }

  /** Run `f` as one transaction: commit on success, roll back and rethrow on failure. */
  private def tx[A](f: Connection => A): A = synchronized {
    try
      val a = f(conn)
      conn.commit()
      a
    catch
      case NonFatal(e) =>
        conn.rollback()
        throw e
  }

  private def update(c: Connection, sql: String)(bind: PreparedStatement => Unit): Int =
    val ps = c.prepareStatement(sql)
    try { bind(ps); ps.executeUpdate() }
    finally ps.close()

  private def query[A](c: Connection, sql: String)(bind: PreparedStatement => Unit)(
      read: ResultSet => A
  ): Vector[A] =
    val ps = c.prepareStatement(sql)
    try
      bind(ps)
      val rs = ps.executeQuery()
      try
        val out = Vector.newBuilder[A]
        while rs.next() do out += read(rs)
        out.result()
      finally rs.close()
    finally ps.close()

  def putUser(u: StoredUser): Unit = tx { c =>
    val ordinal =
      query(c, "SELECT ordinal FROM provider_user WHERE user_id = ?")(_.setString(1, u.user))(
        _.getLong(1)
      ).headOption.getOrElse(
        query(c, "SELECT COALESCE(MAX(ordinal), 0) + 1 FROM provider_user")(_ => ())(
          _.getLong(1)
        ).head
      )
    update(c, "DELETE FROM provider_user WHERE user_id = ?")(_.setString(1, u.user)): Unit
    update(
      c,
      "INSERT INTO provider_user (user_id, ordinal, client_label, session_hash) VALUES (?, ?, ?, ?)"
    ) { ps =>
      ps.setString(1, u.user); ps.setLong(2, ordinal); ps.setBytes(3, u.clientLabel)
      ps.setBytes(4, u.sessionHash.orNull)
    }: Unit
  }

  def users: Vector[StoredUser] = tx { c =>
    query(
      c,
      "SELECT user_id, client_label, session_hash FROM provider_user ORDER BY ordinal"
    )(_ => ())(rs => StoredUser(rs.getString(1), rs.getBytes(2), Option(rs.getBytes(3))))
  }

  def replaceBundle(user: String, slots: Vector[RoundOps]): Unit = tx { c =>
    update(c, "DELETE FROM provider_slot WHERE user_id = ?")(_.setString(1, user)): Unit
    val ps =
      c.prepareStatement("INSERT INTO provider_slot (user_id, round_id, ops) VALUES (?, ?, ?)")
    try
      slots.foreach { s =>
        ps.setString(1, user); ps.setLong(2, s.roundId); ps.setBytes(3, ProviderCodec.encodeOps(s))
        ps.addBatch()
      }
      ps.executeBatch(): Unit
    finally ps.close()
  }

  def takeSlot(user: String, roundId: Long): Option[RoundOps] = tx { c =>
    def key(ps: PreparedStatement) = { ps.setString(1, user); ps.setLong(2, roundId) }
    val found = query(c, "SELECT ops FROM provider_slot WHERE user_id = ? AND round_id = ?")(key)(
      _.getBytes(1)
    ).headOption
    found.foreach(_ =>
      update(c, "DELETE FROM provider_slot WHERE user_id = ? AND round_id = ?")(key)
    )
    found.map(ProviderCodec.decodeOps)
  }

  def dropSlotsBefore(user: String, roundId: Long): Unit = tx { c =>
    update(c, "DELETE FROM provider_slot WHERE user_id = ? AND round_id < ?") { ps =>
      ps.setString(1, user); ps.setLong(2, roundId)
    }: Unit
  }

  def slotCount(user: String): Int = tx { c =>
    query(c, "SELECT COUNT(*) FROM provider_slot WHERE user_id = ?")(_.setString(1, user))(
      _.getInt(1)
    ).head
  }

  def putReceipt(user: String, receipt: StoredReceipt, maxKept: Int): Unit = tx { c =>
    val round = receipt.receipt.roundId
    update(c, "DELETE FROM provider_receipt WHERE user_id = ? AND round_id = ?") { ps =>
      ps.setString(1, user); ps.setLong(2, round)
    }: Unit
    update(c, "INSERT INTO provider_receipt (user_id, round_id, receipt) VALUES (?, ?, ?)") { ps =>
      ps.setString(1, user); ps.setLong(2, round);
      ps.setBytes(3, ProviderCodec.encodeReceipt(receipt))
    }: Unit
    // Keep at most `maxKept`: evict the oldest rounds beyond it (§5).
    val rounds =
      query(c, "SELECT round_id FROM provider_receipt WHERE user_id = ? ORDER BY round_id")(
        _.setString(1, user)
      )(_.getLong(1))
    if rounds.size > maxKept then
      val cutoff = rounds(rounds.size - maxKept - 1)
      update(c, "DELETE FROM provider_receipt WHERE user_id = ? AND round_id <= ?") { ps =>
        ps.setString(1, user); ps.setLong(2, cutoff)
      }: Unit
  }

  def takeReceipt(user: String, roundId: Long): Option[StoredReceipt] = tx { c =>
    def key(ps: PreparedStatement) = { ps.setString(1, user); ps.setLong(2, roundId) }
    val found =
      query(c, "SELECT receipt FROM provider_receipt WHERE user_id = ? AND round_id = ?")(key)(
        _.getBytes(1)
      ).headOption
    found.foreach(_ =>
      update(c, "DELETE FROM provider_receipt WHERE user_id = ? AND round_id = ?")(key)
    )
    found.map(ProviderCodec.decodeReceipt)
  }

  def drainReceipts(user: String): Vector[StoredReceipt] = tx { c =>
    val all = query(c, "SELECT receipt FROM provider_receipt WHERE user_id = ? ORDER BY round_id")(
      _.setString(1, user)
    )(rs => ProviderCodec.decodeReceipt(rs.getBytes(1)))
    update(c, "DELETE FROM provider_receipt WHERE user_id = ?")(_.setString(1, user)): Unit
    all
  }

  def receiptCount(user: String): Int = tx { c =>
    query(c, "SELECT COUNT(*) FROM provider_receipt WHERE user_id = ?")(_.setString(1, user))(
      _.getInt(1)
    ).head
  }

  /** Close the connection. The store is unusable afterwards. */
  def close(): Unit = synchronized(conn.close())

object JdbcProviderStore:
  /** The embedded default: H2 in a local file at `path` (H2 appends `.mv.db`), in PostgreSQL mode so
    * the same SQL runs on both. Survives a restart of the provider process. */
  def embedded(path: java.nio.file.Path): JdbcProviderStore =
    val url = s"jdbc:h2:file:${path.toAbsolutePath};MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE"
    JdbcProviderStore(() => DriverManager.getConnection(url))

  /** A Postgres server: `url` is a `jdbc:postgresql://…` URL (credentials in the URL or the
    * environment, per the driver). */
  def postgres(url: String): JdbcProviderStore =
    require(url.startsWith("jdbc:postgresql:"), "a jdbc:postgresql: URL")
    JdbcProviderStore(() => DriverManager.getConnection(url))
