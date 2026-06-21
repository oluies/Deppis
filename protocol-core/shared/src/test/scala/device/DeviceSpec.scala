package device

import org.scalatest.funsuite.AnyFunSuite
import Device.*

class DeviceSpec extends AnyFunSuite:

  test("a fresh device is online and has seen the start round (T039; US4)"):
    val d = Device.online()
    assert(d.isOnline)
    assert(d.lastSeen == 0L)

  test("online -> offline -> online round-trips back to online"):
    val d = Device.online(100L)
    val (back, _) = d.goOffline(100L).flatMap(_.goOnline(105L)).toOption.get
    assert(back.isOnline)
    assert(back.lastSeen == 105L)

  test("reconnect replays the contiguous (lastSeen, current] missed rounds (US4)"):
    val (_, catchup) = Device.online(100L).goOffline(100L).flatMap(_.goOnline(105L)).toOption.get
    // offline at 100, back at 105 => rounds 101..105 missed (5 rounds)
    assert(catchup.from == 101L)
    assert(catchup.to == 105L)
    assert(catchup.count == 5L)
    assert(!catchup.bounded)
    assert(!catchup.isEmpty)

  test("offline then online at the same round has no missed rounds"):
    val (back, catchup) = Device.online(50L).goOffline(50L).flatMap(_.goOnline(50L)).toOption.get
    assert(back.isOnline)
    assert(catchup.isEmpty)
    assert(catchup.count == 0L)
    assert(catchup == Catchup.none)

  test("missed catch-up is clipped to the retention window for a long offline period"):
    val gone = Device.online(0L).goOffline(0L).toOption.get
    val current = Retention * 3L
    val (back, catchup) = gone.goOnline(current).toOption.get
    assert(back.lastSeen == current)
    assert(catchup.count == Retention)
    assert(catchup.to == current)
    assert(catchup.from == current - Retention + 1L)
    assert(catchup.bounded)

  test("a gap exactly equal to retention is not clipped"):
    val (_, catchup) = Device.online(0L).goOffline(0L).flatMap(_.goOnline(Retention)).toOption.get
    assert(catchup.count == Retention)
    assert(catchup.from == 1L)
    assert(!catchup.bounded)

  test("a gap of retention + 1 is clipped by exactly one round"):
    val (_, catchup) =
      Device.online(0L).goOffline(0L).flatMap(_.goOnline(Retention + 1L)).toOption.get
    assert(catchup.count == Retention)
    assert(catchup.from == 2L)
    assert(catchup.bounded)

  test("going offline while already offline is rejected"):
    val gone = Device.online(10L).goOffline(10L).toOption.get
    assert(gone.goOffline(12L) == Left("already offline"))

  test("going online while already online is rejected (idempotency guard)"):
    assert(Device.online(10L).goOnline(12L) == Left("already online"))

  test("rounds never move backwards on offline or online"):
    assert(Device.online(10L).goOffline(5L) == Left("round precedes last seen"))
    val gone = Device.online(10L).goOffline(10L).toOption.get
    assert(gone.goOnline(5L) == Left("round precedes last seen"))

  test("advance moves a live device forward with nothing to catch up"):
    val moved = Device.online(10L).advance(20L).toOption.get
    assert(moved.isOnline)
    assert(moved.lastSeen == 20L)

  test("advance is rejected while offline and on backwards rounds"):
    val gone = Device.online(10L).goOffline(10L).toOption.get
    assert(gone.advance(20L) == Left("device is offline"))
    assert(Device.online(10L).advance(5L) == Left("round precedes last seen"))

  test("Device.offline constructs a device offline as of the given round"):
    val d = Device.offline(42L)
    assert(d.isOffline)
    assert(d.lastSeen == 42L)
    val (back, catchup) = d.goOnline(44L).toOption.get
    assert(back.lastSeen == 44L)
    assert(catchup.from == 43L)
    assert(catchup.to == 44L)

  test("equality is by value over presence, lastSeen and offline marker"):
    assert(Device.online(7L) == Device.online(7L))
    assert(Device.online(7L) != Device.online(8L))
    assert(Device.online(7L) != Device.offline(7L))
    assert(Device.online(7L).hashCode == Device.online(7L).hashCode)

  test("successive offline/online cycles accumulate seen rounds correctly"):
    val d0 = Device.online(0L)
    val (d1, c1) = d0.goOffline(0L).flatMap(_.goOnline(3L)).toOption.get
    assert(c1.from == 1L && c1.to == 3L)
    val (d2, c2) = d1.goOffline(3L).flatMap(_.goOnline(7L)).toOption.get
    assert(c2.from == 4L && c2.to == 7L)
    assert(d2.lastSeen == 7L)
