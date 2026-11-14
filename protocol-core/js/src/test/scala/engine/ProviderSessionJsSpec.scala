package engine

import delegation.FakeProvider
import org.scalatest.funsuite.AsyncFunSuite

import scala.collection.mutable
import scala.concurrent.Future
import scala.scalajs.js
import scala.scalajs.js.JSConverters.*
import scala.scalajs.js.typedarray.Uint8Array

/** The exported browser API (`ProtocolEngine` + `ProviderSession`) driven exactly as a browser host
  * would: through a [[JsProviderApi]] whose methods return real JS Promises and move `Uint8Array`s
  * and plain JS objects. It sits over the in-memory [[FakeProvider]], so this checks the facade —
  * byte and shape conversions, Promise plumbing, the provider-routed engine constructor — and that
  * the T037 scenario still holds through it. */
class ProviderSessionJsSpec extends AsyncFunSuite:

  // Real JS Promises resolve on the JS event loop, which ScalaTest's default serial execution
  // context cannot drain ("Queue is empty while future is not completed"). Run on the JS queue, as a
  // browser does.
  override implicit def executionContext: scala.concurrent.ExecutionContext =
    scala.concurrent.ExecutionContext.global

  /** A host's JsProviderApi over the fake provider, converting through the documented JS shapes. */
  private def hostApi(p: FakeProvider): JsProviderApi =
    def bytes(a: js.Any): Array[Byte] = Uint8.toBytes(a.asInstanceOf[Uint8Array])
    def sig(d: js.Dynamic) = RoundSignal(bytes(d.label), d.bit.asInstanceOf[Int])
    def ops(d: js.Dynamic) = RoundOps(
      d.roundId.asInstanceOf[Double].toLong,
      bytes(d.writeToken),
      bytes(d.frame),
      sig(d.signal),
      sig(d.fallbackSignal),
      bytes(d.readToken)
    )
    def done[A](f: Future[A]): js.Promise[A] = f.toJSPromise
    js.Dynamic
      .literal(
        register =
          (u: String, l: Uint8Array) => done(p.register(u, Uint8.toBytes(l)).map(_.isRight)),
        uploadBundle = (u: String, from: Double, slots: js.Array[js.Dynamic]) =>
          done(
            p.uploadBundle(u, DelegationBundle(from.toLong, slots.toVector.map(ops))).map(_.isRight)
          ),
        getDigest =
          (u: String, r: Double) => done(p.digestFor(u, r.toLong).map(_.map(Uint8.toJs).orNull)),
        submitLive = (u: String, o: js.Dynamic) => done(p.submitLive(u, ops(o))),
        collectReceipt = (u: String, r: Double) =>
          done(
            p.collectReceipt(u, r.toLong)
              .map(_.map { rc =>
                js.Dynamic.literal(
                  roundId = rc.roundId.toDouble,
                  ranLive = rc.ranLive,
                  writeAccepted = rc.writeAccepted,
                  retrieved = rc.retrieved.map(Uint8.toJs).orNull
                )
              }.orNull)
          ),
        collectAll = (u: String) => done(p.collectAll(u).map(_.toDouble))
      )
      .asInstanceOf[JsProviderApi]

  test("a provider-routed ProtocolEngine keeps its label and starts with no transport"):
    val e = EngineJs(js.undefined, Uint8.toJs("alice".getBytes("UTF-8")))
    assert(e.underlying.privacyStatus.metadataPrivate == false)

  test("T037 through the exported ProviderSession over Promise-based host calls"):
    val p = FakeProvider()
    val aLabel = Uint8.toJs("alice".getBytes("UTF-8"))
    val bLabel = Uint8.toJs("bob".getBytes("UTF-8"))
    val alice = EngineJs(js.undefined, aLabel)
    val bob = EngineJs(js.undefined, bLabel)
    val oob = "js-session-oob".getBytes("UTF-8")
    val pid =
      alice.underlying
        .addBuddy(oob, BuddyRole.Initiator, peerNotifyLabel = Uint8.toBytes(bLabel))
        .toOption
        .get
        .pairId
    bob.underlying
      .addBuddy(oob, BuddyRole.Responder, peerNotifyLabel = Uint8.toBytes(aLabel))
      .toOption
      .get: Unit
    alice.underlying.confirmBuddy(pid, matched = true).toOption.get
    bob.underlying.confirmBuddy(pid, matched = true).toOption.get
    alice.underlying.drainEvents(); bob.underlying.drainEvents()

    val api = hostApi(p)
    val sched = Seq[js.UndefOr[Double]](0.0, 1000.0, 600.0)
    def session(e: EngineJs, user: String, l: Uint8Array) =
      // 1 s rounds need proportionally small clock margins (the defaults fit 15 s rounds).
      ProviderSessionJs(e, api, user, l, 20, 120, sched(0), sched(1), sched(2), 50.0, 50.0, 100.0)
    val sa = session(alice, "alice", aLabel)
    val sb = session(bob, "bob", bLabel)
    var aliceUp = true
    var bobUp = true
    var now = 1000.0
    val toBob = mutable.ArrayBuffer.empty[String]
    def runUntil(round: Long): Future[Unit] =
      if now >= round * 1000.0 then Future.unit
      else
        val r = (now / 1000).toLong
        if now == r * 1000.0 then p.openRound(r)
        if now == r * 1000.0 + 600 then p.closeRound(r)
        val a = if aliceUp then sa.step(now).toFuture else Future.unit
        a.flatMap(_ => if bobUp then sb.step(now).toFuture else Future.unit).flatMap { _ =>
          toBob ++= bob.underlying.drainEvents().collect {
            case EngineEvent.MessageReceived(_, t, _) => t
          }
          alice.underlying.drainEvents(): Unit
          now += 50
          runUntil(round)
        }
    for
      _ <- sa.start(1).toFuture
      _ <- sb.start(1).toFuture
      _ <- runUntil(11)
      _ = bobUp = false
      _ = alice.underlying.sendMessage(pid, "m1")
      _ = alice.underlying.sendMessage(pid, "m2")
      _ <- runUntil(31)
      _ = aliceUp = false
      _ <- runUntil(60)
      _ = bobUp = true
      _ <- sb.collectAway().toFuture
      _ <- runUntil(90)
      _ = assert(toBob == Seq("m1"), s"m1 from alice's bundle while she is away: $toBob")
      _ = aliceUp = true
      _ <- runUntil(120)
    yield assert(toBob == Seq("m1", "m2"), s"m2 follows in order, each once: $toBob")

  test("margins that leave no submit window are refused at construction"):
    val label = Uint8.toJs("dave".getBytes("UTF-8"))
    val e = EngineJs(js.undefined, label)
    // 600 ms cutoff with the default 500 ms open grace + 1000 ms submit margin: no window at all.
    val err = intercept[IllegalArgumentException](
      ProviderSessionJs(e, hostApi(FakeProvider()), "dave", label, 20, 120, 0.0, 1000.0, 600.0)
    )
    assert(err.getMessage.contains("no window"))

  test("a rejected host Promise is a refusal, never an exception escaping a round"):
    val failing = js.Dynamic
      .literal(
        register = (_: String, _: Uint8Array) => js.Promise.reject("network down"),
        uploadBundle = (_: String, _: Double, _: js.Array[js.Dynamic]) => js.Promise.reject("x"),
        getDigest = (_: String, _: Double) => js.Promise.reject("x"),
        submitLive = (_: String, _: js.Dynamic) => js.Promise.reject("x"),
        collectReceipt = (_: String, _: Double) => js.Promise.reject("x"),
        collectAll = (_: String) => js.Promise.reject("x")
      )
      .asInstanceOf[JsProviderApi]
    val label = Uint8.toJs("carol".getBytes("UTF-8"))
    val s = ProviderSessionJs(EngineJs(js.undefined, label), failing, "carol", label)
    for
      handedIn <- s.beforeCutoff(5).toFuture
      away <- s.collectAway().toFuture
      started <- s.start(1).toFuture.map(_ => "started").recover { case _ => "refused" }
    yield
      assert(!handedIn, "no digest ⇒ nothing handed in")
      assert(away == 0)
      assert(started == "refused", "a refused registration fails start(), visibly")
