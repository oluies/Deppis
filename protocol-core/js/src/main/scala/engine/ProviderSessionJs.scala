package engine

import delegation.{DeviceClock, DeviceSession, ProviderPort, RoundSchedule}

import scala.concurrent.{ExecutionContext, Future}
import scala.scalajs.js
import scala.scalajs.js.JSConverters.*
import scala.scalajs.js.annotation.{JSExport, JSExportTopLevel}
import scala.scalajs.js.typedarray.Uint8Array

/** The provider calls a browser host implements (`design/offline-delegation.md` §3; contract
  * `provider.proto`) — one Promise-returning method per RPC, typically over gRPC-web via Envoy. The
  * host moves opaque bytes only: it never sees plaintext or keys, and it adds the session secret
  * `Register` returned to every later call itself.
  *
  * Shapes (plain JS objects, bytes as `Uint8Array`, round ids as safe-integer numbers):
  * {{{
  *   RoundOps = { roundId, writeToken, frame, signal: { label, bit },
  *                fallbackSignal: { label, bit }, readToken }
  *   Receipt  = { roundId, ranLive, writeAccepted, retrieved /* Uint8Array or null */ }
  * }}}
  * `getDigest` and `collectReceipt` resolve to `null` when there is nothing; a rejected Promise is
  * treated like a refusal — the round's bundle slot runs instead. */
@js.native
trait JsProviderApi extends js.Object:
  def register(user: String, clientLabel: Uint8Array): js.Promise[Boolean] = js.native
  def uploadBundle(
      user: String,
      fromRound: Double,
      slots: js.Array[js.Dynamic]
  ): js.Promise[Boolean] =
    js.native
  def getDigest(user: String, roundId: Double): js.Promise[Uint8Array] = js.native
  def submitLive(user: String, ops: js.Dynamic): js.Promise[Boolean] = js.native
  def collectReceipt(user: String, roundId: Double): js.Promise[js.Dynamic] = js.native
  def collectAll(user: String): js.Promise[Double] = js.native

/** Byte/shape conversions between the engine's round types and the JS shapes above. */
private[engine] object ProviderJs:
  def round(r: Double): Long =
    require(
      r >= 0 && r <= JsRoundTransport.MaxSafeRound.toDouble && r == math.floor(r),
      "round id out of JS-safe-integer range"
    )
    r.toLong
  def jsRound(r: Long): Double =
    require(r >= 0 && r <= JsRoundTransport.MaxSafeRound, "round id out of JS-safe-integer range")
    r.toDouble

  private def signal(s: RoundSignal) = js.Dynamic.literal(label = Uint8.toJs(s.label), bit = s.bit)

  def toJs(o: RoundOps): js.Dynamic =
    js.Dynamic.literal(
      roundId = jsRound(o.roundId),
      writeToken = Uint8.toJs(o.writeToken),
      frame = Uint8.toJs(o.frame),
      signal = signal(o.signal),
      fallbackSignal = signal(o.fallbackSignal),
      readToken = Uint8.toJs(o.readToken)
    )

  def receipt(d: js.Dynamic): RoundReceipt =
    val retrieved = d.retrieved.asInstanceOf[Uint8Array]
    RoundReceipt(
      round(d.roundId.asInstanceOf[Double]),
      d.ranLive.asInstanceOf[Boolean],
      d.writeAccepted.asInstanceOf[Boolean],
      Option(retrieved).map(Uint8.toBytes)
    )

/** [[JsProviderApi]] as the shared [[ProviderPort]]. A rejected Promise becomes the safe answer for
  * each call — refused, absent, or a failed setup step — never an exception escaping into a round. */
private[engine] final class JsProviderPort(api: JsProviderApi)(using ec: ExecutionContext)
    extends ProviderPort:
  private def safe[A](p: => js.Promise[A], fallback: A): Future[A] =
    try p.toFuture.recover { case _ => fallback }
    catch case _: js.JavaScriptException => Future.successful(fallback)

  def register(user: String, clientLabel: Array[Byte]) =
    safe(api.register(user, Uint8.toJs(clientLabel)), false)
      .map(ok => if ok then Right(()) else Left("provider refused the registration"))
  def uploadBundle(user: String, bundle: DelegationBundle) =
    safe(
      api.uploadBundle(
        user,
        ProviderJs.jsRound(bundle.fromRound),
        bundle.slots.map(ProviderJs.toJs).toJSArray
      ),
      false
    ).map(ok => if ok then Right(()) else Left("provider refused the bundle"))
  def digestFor(user: String, roundId: Long) =
    safe(api.getDigest(user, ProviderJs.jsRound(roundId)), null).map(d =>
      Option(d).map(Uint8.toBytes)
    )
  def submitLive(user: String, ops: RoundOps) =
    safe(api.submitLive(user, ProviderJs.toJs(ops)), false)
  def collectReceipt(user: String, roundId: Long) =
    safe(api.collectReceipt(user, ProviderJs.jsRound(roundId)), null)
      .map(d => Option(d.asInstanceOf[js.Any]).map(_ => ProviderJs.receipt(d)))
  def collectAll(user: String) = safe(api.collectAll(user), 0.0).map(_.toInt)

/** The browser device's provider session (`design/offline-delegation.md` §3): drives a
  * provider-routed [[EngineJs]] through a host-implemented [[JsProviderApi]], using the SAME shared
  * [[delegation.DeviceSession]] and [[delegation.DeviceClock]] the JVM runs. The async host calls
  * replace the old Web-Worker/SharedArrayBuffer plan (grpc-web-transport.md Option A): the engine's
  * round is already split into `beginRound` / `applyReceipt`, so nothing has to block.
  *
  * {{{
  *   const engine  = new ProtocolEngine(undefined, label);
  *   const session = new ProviderSession(engine, providerApi, "alice", label);
  *   await session.start(firstRound);
  *   setInterval(() => session.step(Date.now()), 250); // while the app is in the foreground
  * }}}
  *
  * Schedule: `epochMillis` / `intervalMillis` / `cutoffMillis` default to the network-wide
  * [[delegation.RoundSchedule]] (15 s rounds, 10 s cutoff, epoch 0); H and F to [[Delegation]];
  * the clock margins (`openGraceMillis` 500, `closeGraceMillis` 500, `submitMarginMillis` 1000) to
  * [[delegation.DeviceClock]]'s, which reject a combination that leaves no submit window. Labeled DEV like everything provider-routed until Phase 4. */
@JSExportTopLevel("ProviderSession")
final class ProviderSessionJs(
    engine: EngineJs,
    api: JsProviderApi,
    user: String,
    clientLabel: Uint8Array,
    refreshEveryRounds: js.UndefOr[Int] = js.undefined,
    horizonRounds: js.UndefOr[Int] = js.undefined,
    epochMillis: js.UndefOr[Double] = js.undefined,
    intervalMillis: js.UndefOr[Double] = js.undefined,
    cutoffMillis: js.UndefOr[Double] = js.undefined,
    openGraceMillis: js.UndefOr[Double] = js.undefined,
    closeGraceMillis: js.UndefOr[Double] = js.undefined,
    submitMarginMillis: js.UndefOr[Double] = js.undefined
):
  private given ExecutionContext = ExecutionContext.global // the JS event queue under Scala.js

  private val defaults = RoundSchedule()
  private val session = DeviceSession(
    user,
    engine.underlying,
    JsProviderPort(api),
    Uint8.toBytes(clientLabel),
    refreshEveryRounds.getOrElse(Delegation.RefreshEveryRounds),
    horizonRounds.getOrElse(Delegation.HorizonRounds)
  )
  private val clock = DeviceClock(
    session,
    RoundSchedule(
      epochMillis.map(_.toLong).getOrElse(defaults.epochMillis),
      intervalMillis.map(_.toLong).getOrElse(defaults.intervalMillis),
      cutoffMillis.map(_.toLong).getOrElse(defaults.cutoffMillis)
    ),
    openGraceMillis.map(_.toLong).getOrElse(500L),
    closeGraceMillis.map(_.toLong).getOrElse(500L),
    submitMarginMillis.map(_.toLong).getOrElse(1_000L)
  )

  /** Register with the provider and upload the first standing bundle, from `firstRound`. */
  @JSExport def start(firstRound: Double): js.Promise[Unit] =
    session.start(ProviderJs.round(firstRound)).toJSPromise

  /** Advance this device to `nowMillis` (e.g. `Date.now()`); a no-op while a step is in flight. */
  @JSExport def step(nowMillis: Double): js.Promise[Unit] = clock.step(nowMillis.toLong).toJSPromise

  /** Hand in the live set for `round` (if its digest is available); resolves to whether accepted. */
  @JSExport def beforeCutoff(round: Double): js.Promise[Boolean] =
    session.beforeCutoff(ProviderJs.round(round)).toJSPromise

  /** Apply `round`'s receipt and refresh the bundle on the cadence. */
  @JSExport def afterCutoff(round: Double): js.Promise[Unit] =
    session.afterCutoff(ProviderJs.round(round)).toJSPromise

  /** Back after an absence: drop what the provider kept; resolves to how many receipts. */
  @JSExport def collectAway(): js.Promise[Double] =
    session.collectAway().map(_.toDouble).toJSPromise
