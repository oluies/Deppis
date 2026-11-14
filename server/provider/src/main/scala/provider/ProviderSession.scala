package provider

import delegation.{DeviceSession, ProviderPort}
import engine.{Delegation, DelegationBundle, Engine, RoundOps, RoundReceipt}

import scala.concurrent.duration.Duration
import scala.concurrent.{Await, ExecutionContext, Future}
import scala.util.Try

/** The device side of provider routing on the JVM: a synchronous wrapper over the shared
  * [[delegation.DeviceSession]] — the same protocol logic the browser runs — driving one device's
  * [[engine.Engine]] through its provider, in-process [[Provider]] or networked, via [[ProviderApi]].
  *
  * [[ProviderApi]] answers synchronously, so every future here is already complete when it is
  * awaited (the `parasitic` execution context runs continuations in place); a provider error
  * surfaces as the exception it always did.
  *
  * Registers the device and uploads a first bundle at construction. See [[DeviceSession]] for the
  * per-round contract; [[collectAway]] still returns the kept receipts themselves (JVM callers and
  * tests inspect them). */
final class ProviderSession(
    val user: String,
    engine: Engine,
    provider: ProviderApi,
    clientLabel: Array[Byte],
    val refreshEveryRounds: Int = Delegation.RefreshEveryRounds,
    val horizonRounds: Int = Delegation.HorizonRounds,
    firstRound: Long = 1L
):
  private given ExecutionContext = ExecutionContext.parasitic

  private[provider] val core: DeviceSession =
    DeviceSession(
      user,
      engine,
      ProviderSession.SyncPort(provider),
      clientLabel,
      refreshEveryRounds,
      horizonRounds
    )
  ProviderSession.await(core.start(firstRound))

  /** See [[DeviceSession.beforeCutoff]]. */
  def beforeCutoff(roundId: Long): Boolean = ProviderSession.await(core.beforeCutoff(roundId))

  /** See [[DeviceSession.afterCutoff]]. */
  def afterCutoff(roundId: Long): Unit = ProviderSession.await(core.afterCutoff(roundId))

  /** See [[DeviceSession.refreshBundle]]. */
  def refreshBundle(fromRound: Long): Unit = ProviderSession.await(core.refreshBundle(fromRound))

  /** Back after an absence: take everything the provider kept for this device. */
  def collectAway(): Vector[StoredReceipt] = provider.collectAll(user)

object ProviderSession:
  private[provider] def await[A](f: Future[A]): A = Await.result(f, Duration.Inf)

  /** [[ProviderApi]] as a [[ProviderPort]]: each call made in place, its result (or exception)
    * wrapped in an already-completed future. */
  private[provider] final class SyncPort(api: ProviderApi) extends ProviderPort:
    def register(user: String, clientLabel: Array[Byte]) =
      Future.fromTry(Try(api.register(user, clientLabel)))
    def uploadBundle(user: String, bundle: DelegationBundle) =
      Future.fromTry(Try(api.uploadBundle(user, bundle)))
    def digestFor(user: String, roundId: Long) = Future.fromTry(Try(api.digestFor(user, roundId)))
    def submitLive(user: String, ops: RoundOps) = Future.fromTry(Try(api.submitLive(user, ops)))
    def collectReceipt(user: String, roundId: Long): Future[Option[RoundReceipt]] =
      Future.fromTry(Try(api.collectReceipt(user, roundId).map(_.receipt)))
    def collectAll(user: String) = Future.fromTry(Try(api.collectAll(user).size))
